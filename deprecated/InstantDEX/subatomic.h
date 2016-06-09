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

#ifndef xcode_subatomic_h
#define xcode_subatomic_h

//https://bitcointalk.org/index.php?topic=1172153.0

#include <stdbool.h>

struct bp_key { void *k; };
typedef struct cstring {
	char	*str;		// string data, incl. NUL
	size_t	len;		// length of string, not including NUL
	size_t	alloc;		// total allocated buffer length
} cstring;

extern bool bp_key_init(struct bp_key *key);
extern void bp_key_free(struct bp_key *key);
extern bool bp_key_generate(struct bp_key *key);
extern bool bp_privkey_set(struct bp_key *key, const void *privkey, size_t pk_len);
extern bool bp_pubkey_set(struct bp_key *key, const void *pubkey, size_t pk_len);
extern bool bp_key_secret_set(struct bp_key *key, const void *privkey_, size_t pk_len);
extern bool bp_privkey_get(const struct bp_key *key, void **privkey, size_t *pk_len);
extern bool bp_pubkey_get(const struct bp_key *key, void **pubkey, size_t *pk_len);
extern bool bp_key_secret_get(void *p, size_t len, const struct bp_key *key);
extern bool bp_sign(const struct bp_key *key, const void *data, size_t data_len,void **sig_, size_t *sig_len_);
extern bool bp_verify(const struct bp_key *key, const void *data, size_t data_len,const void *sig, size_t sig_len);

void cstr_free(cstring *s, bool free_buf);
cstring *base58_encode_check(unsigned char addrtype,bool have_addrtype,const void *data,size_t data_len);
cstring *base58_decode_check(unsigned char *addrtype, const char *s_in);
int32_t btc_setprivkey(struct bp_key *key,char *privkeystr);
int32_t btc_getpubkey(char pubkeystr[67],uint8_t pubkeybuf[33],struct bp_key *key);
void btc_freekey(void *key);

struct btcaddr
{
	struct bp_key key;
    uint8_t *pubkey; uint16_t p2sh;
    char addr[36],coin[8];
    uint8_t privkey[280];
};

#define SCRIPT_OP_IF 0x63
#define SCRIPT_OP_ELSE 0x67
#define SCRIPT_OP_DUP 0x76
#define SCRIPT_OP_ENDIF 0x68
#define SCRIPT_OP_TRUE 0x51
#define SCRIPT_OP_2 0x52
#define SCRIPT_OP_3 0x53
#define SCRIPT_OP_EQUALVERIFY 0x88
#define SCRIPT_OP_HASH160 0xa9
#define SCRIPT_OP_EQUAL 0x87
#define SCRIPT_OP_CHECKSIG 0xac
#define SCRIPT_OP_CHECKMULTISIG 0xae
#define SCRIPT_OP_CHECKMULTISIGVERIFY 0xaf

char *create_atomictx_scripts(uint8_t addrtype,char *scriptPubKey,char *p2shaddr,char *pubkeyA,char *pubkeyB,char *hash160str)
{
    // if ( refund ) OP_HASH160 <2of2 multisig hash> OP_EQUAL   // standard multisig
    // else OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG // standard spend
    cstring *btc_addr; char *retstr; uint8_t pubkeyAbytes[33],pubkeyBbytes[33],hash160[20],tmpbuf[24],hex[4096]; int32_t i,n = 0;
    decode_hex(pubkeyAbytes,33,pubkeyA);
    decode_hex(pubkeyBbytes,33,pubkeyB);
    decode_hex(hash160,20,hash160str);
    hex[n++] = SCRIPT_OP_IF;
    hex[n++] = SCRIPT_OP_2;
    hex[n++] = 33, memcpy(&hex[n],pubkeyAbytes,33), n += 33;
    hex[n++] = 33, memcpy(&hex[n],pubkeyBbytes,33), n += 33;
    hex[n++] = SCRIPT_OP_2;
    hex[n++] = SCRIPT_OP_CHECKMULTISIG;
    hex[n++] = SCRIPT_OP_ELSE;
    hex[n++] = SCRIPT_OP_DUP;
    hex[n++] = SCRIPT_OP_HASH160;
    hex[n++] = 20; memcpy(&hex[n],hash160,20); n += 20;
    hex[n++] = SCRIPT_OP_EQUALVERIFY;
    hex[n++] = SCRIPT_OP_CHECKSIG;
    hex[n++] = SCRIPT_OP_ENDIF;
    if ( (retstr= calloc(1,n*2+16)) == 0 )
        return(0);
    //printf("pubkeyA.(%s) pubkeyB.(%s) hash160.(%s) ->\n",pubkeyA,pubkeyB,hash160str);
    //strcpy(retstr,"01");
    //sprintf(retstr+2,"%02x",n);
    for (i=0; i<n; i++)
    {
        retstr[i*2] = hexbyte((hex[i]>>4) & 0xf);
        retstr[i*2 + 1] = hexbyte(hex[i] & 0xf);
        //printf("%02x",hex[i]);
    }
    retstr[n*2] = 0;
    calc_OP_HASH160(scriptPubKey,tmpbuf+2,retstr);
    tmpbuf[0] = SCRIPT_OP_HASH160;
    tmpbuf[1] = 20;
    tmpbuf[22] = SCRIPT_OP_EQUAL;
    init_hexbytes_noT(scriptPubKey,tmpbuf,23);
    if ( p2shaddr != 0 )
    {
        p2shaddr[0] = 0;
        if ( (btc_addr= base58_encode_check(addrtype,true,tmpbuf+2,20)) != 0 )
        {
            if ( strlen(btc_addr->str) < 36 )
                strcpy(p2shaddr,btc_addr->str);
            cstr_free(btc_addr,true);
        }
    }
    return(retstr);
}

#ifdef noiguana
int32_t create_MofN(uint8_t addrtype,char *redeemScript,char *scriptPubKey,char *p2shaddr,char *pubkeys[],int32_t M,int32_t N)
{
    cstring *btc_addr; uint8_t pubkey[33],tmpbuf[24],hex[4096]; int32_t i,n = 0;
    hex[n++] = 0x50 + M;
    for (i=0; i<N; i++)
    {
        decode_hex(pubkey,33,pubkeys[i]);
        hex[n++] = 33;
        memcpy(&hex[n],pubkey,33);
        n += 33;
    }
    hex[n++] = 0x50 + N;
    hex[n++] = SCRIPT_OP_CHECKMULTISIG;
    for (i=0; i<n; i++)
    {
        redeemScript[i*2] = hexbyte((hex[i]>>4) & 0xf);
        redeemScript[i*2 + 1] = hexbyte(hex[i] & 0xf);
        //fprintf(stderr,"%02x",hex[i]);
    }
    //fprintf(stderr," n.%d\n",n);
    redeemScript[n*2] = 0;
    calc_OP_HASH160(0,tmpbuf+2,redeemScript);
    //printf("op160.(%s)\n",redeemScript);
    tmpbuf[0] = SCRIPT_OP_HASH160;
    tmpbuf[1] = 20;
    tmpbuf[22] = SCRIPT_OP_EQUAL;
    init_hexbytes_noT(scriptPubKey,tmpbuf,23);
    p2shaddr[0] = 0;
    if ( (btc_addr= base58_encode_check(addrtype,true,tmpbuf+2,20)) != 0 )
    {
        if ( strlen(btc_addr->str) < 36 )
            strcpy(p2shaddr,btc_addr->str);
        cstr_free(btc_addr,true);
    }
    return(n);
}

struct btcaddr *btcaddr_new(char *coinstr,char *p2sh_script)
{
    uint8_t script[8192],md160[20]; char pubkeystr[512],privkeystr[512],hashstr[41]; struct coin777 *coin;
    void *privkey=0,*pubkey=0; int32_t n; size_t len,slen; cstring *btc_addr; struct btcaddr *btc;
    if ( (btc= calloc(1,sizeof(*btc))) == 0 || (coin = coin777_find(coinstr,1)) == 0 )
    {
        if ( btc != 0 )
            free(btc);
        return(0);
    }
    strncpy(btc->coin,coin->name,sizeof(btc->coin)-1);
    if ( p2sh_script != 0 )
    {
        calc_OP_HASH160(0,md160,p2sh_script);
        btc->p2sh = n = (int32_t)strlen(p2sh_script) >> 1;
        decode_hex(script,n,p2sh_script);
        if ( (btc_addr= base58_encode_check(coin->p2shtype,true,md160,sizeof(md160))) != 0 )
        {
            if ( n > sizeof(btc->privkey)-23 )
            {
                printf("script.(%s) len.%d is too big\n",p2sh_script,n);
                free(btc);
                return(0);
            }
            strcpy(btc->addr,btc_addr->str);
            memcpy(btc->privkey,script,n);
            btc->pubkey = &btc->privkey[sizeof(btc->privkey) - 23];
            btc->pubkey[0] = SCRIPT_OP_HASH160;
            btc->pubkey[2] = 20;
            memcpy(&btc->pubkey[2],md160,20);
            btc->pubkey[22] = SCRIPT_OP_EQUAL;
            init_hexbytes_noT(privkeystr,script,n);
            printf("type.%u btcaddr.%ld addr.(%s) %ld p2sh.(%s) %d\n",coin->p2shtype,(long)sizeof(struct btcaddr),btc->addr,(long)strlen(btc->addr),privkeystr,n);
            cstr_free(btc_addr,true);
        } else free(btc), btc = 0;
        return(btc);
    }
    else if ( bp_key_init(&btc->key) != 0 && bp_key_generate(&btc->key) != 0 && bp_pubkey_get(&btc->key,&pubkey,&len) != 0 && bp_privkey_get(&btc->key,&privkey,&slen) != 0 )
    {
        if ( len == 33 && slen == 214 && memcmp((void *)((long)privkey + slen - 33),pubkey,33) == 0 )
        {
            init_hexbytes_noT(pubkeystr,pubkey,len);
            init_hexbytes_noT(privkeystr,privkey,slen);
            calc_OP_HASH160(hashstr,md160,pubkeystr);
            if ( (btc_addr= base58_encode_check(coin->addrtype,true,md160,sizeof(md160))) != 0 )
            {
                strcpy(btc->addr,btc_addr->str);
                memcpy(btc->privkey,privkey,slen);
                btc->pubkey = &btc->privkey[slen - len];
                printf("type.%u btcaddr.%ld rmd160.(%s) addr.(%s) %ld pubkey.(%s) %d privkey.(%s) %d\n",coin->addrtype,(long)sizeof(struct btcaddr),hashstr,btc->addr,(long)strlen(btc->addr),pubkeystr,(int32_t)len,privkeystr,(int32_t)slen);
                cstr_free(btc_addr,true);
            }
            else free(btc), btc = 0;
        } else free(btc), btc = 0;
    }
    return(btc);
}

int32_t btc_getpubkey(char pubkeystr[67],uint8_t pubkeybuf[33],struct bp_key *key)
{
    void *pubkey = 0; size_t len = 0;
    bp_pubkey_get(key,&pubkey,&len);
    if ( pubkey != 0 )
    {
        if ( pubkeystr != 0 )
        {
            if ( len < 34 )
            {
                init_hexbytes_noT(pubkeystr,pubkey,(int32_t)len);
                memcpy(pubkeybuf,pubkey,len);
            }
            else printf("btc_getpubkey error len.%d\n",(int32_t)len), len = -1;
        }
        //printf("btc_getpubkey len.%ld (%s).%p\n",len,pubkeystr,pubkeystr);
    } else len = -1;
    return((int32_t)len);
}

int32_t btc_convrmd160(char *coinaddr,uint8_t addrtype,uint8_t md160[20])
{
    cstring *btc_addr;
    if ( (btc_addr= base58_encode_check(addrtype,true,md160,20)) != 0 )
    {
        strcpy(coinaddr,btc_addr->str);
        cstr_free(btc_addr,true);
        return(0);
    }
    return(-1);
}

int32_t btc_coinaddr(char *coinaddr,uint8_t addrtype,char *pubkeystr)
{
    uint8_t rmd160[20]; char hashstr[41];
    calc_OP_HASH160(hashstr,rmd160,pubkeystr);
    return(btc_convrmd160(coinaddr,addrtype,rmd160));
}

int32_t btc_convaddr(char *hexaddr,char *addr58)
{
    uint8_t addrtype; cstring *cstr;
    if ( (cstr= base58_decode_check(&addrtype,(const char *)addr58)) != 0 )
    {
        sprintf(hexaddr,"%02x",addrtype);
        init_hexbytes_noT(hexaddr+2,(void *)cstr->str,cstr->len);
        cstr_free(cstr,true);
        return(0);
    }
    return(-1);
}

int32_t btc_priv2wip(char *wipstr,uint8_t privkey[32],uint8_t addrtype)
{
    uint8_t tmp[128]; char hexstr[67]; cstring *btc_addr;
    memcpy(tmp,privkey,32);
    tmp[32] = 1;
    init_hexbytes_noT(hexstr,tmp,32);
    if ( (btc_addr= base58_encode_check(addrtype,true,tmp,33)) != 0 )
    {
        strcpy(wipstr,btc_addr->str);
        cstr_free(btc_addr,true);
    }
    printf("-> (%s) -> wip.(%s) addrtype.%02x\n",hexstr,wipstr,addrtype);
    return(0);
}

int32_t btc_wip2priv(uint8_t privkey[32],char *wipstr)
{
    uint8_t addrtype; cstring *cstr; int32_t len = -1;
    if ( (cstr= base58_decode_check(&addrtype,(const char *)wipstr)) != 0 )
    {
        init_hexbytes_noT((void *)privkey,(void *)cstr->str,cstr->len);
        if ( cstr->str[cstr->len-1] == 0x01 )
            cstr->len--;
        memcpy(privkey,cstr->str,cstr->len);
        len = (int32_t)cstr->len;
        char tmp[138];
        btc_priv2wip(tmp,privkey,addrtype);
        printf("addrtype.%02x wipstr.(%llx) len.%d\n",addrtype,*(long long *)privkey,len);
        cstr_free(cstr,true);
    }
    return(len);
}

int32_t btc_setprivkey(struct bp_key *key,char *privkeystr)
{
    uint8_t privkey[512]; int32_t len = btc_wip2priv(privkey,privkeystr);
    if ( len < 0 || bp_key_init(key) == 0 || bp_key_secret_set(key,privkey,len) == 0 )
    {
        printf("error setting privkey\n");
        return(-1);
    }
    return(0);
}

void jumblr_freekey(void *key)
{
    bp_key_free(key);
    free(key);
}

int32_t btc_priv2pub(uint8_t pubkey[33],uint8_t privkey[32])
{
    size_t len; void *pub = 0; int32_t retval = -1;
    struct bp_key *key = calloc(1,sizeof(*key));
    if ( key != 0 && bp_key_init(key) != 0 && bp_key_secret_set(key,privkey,32) != 0 )
    {
        bp_pubkey_get(key,&pub,&len);
        bp_key_free(key);
        if ( len == 33 )
            memcpy(pubkey,pub,33);
        if ( pub != 0 )
            free(pub);
        return(retval);
    }
    if ( key != 0 )
        bp_key_free(key);
    return(retval);
}

int32_t btc_pub2rmd(uint8_t rmd160[20],uint8_t pubkey[33])
{
    char pubkeystr[67],hashstr[41];
    init_hexbytes_noT(pubkeystr,pubkey,33);
    calc_OP_HASH160(hashstr,rmd160,pubkeystr);
    return(0);
}

void *jumblr_bpkey(char *pubP,struct coin777 *coin,char *coinaddr)
{
    uint8_t buf[2048]; char *privkey; struct bp_key *key = 0;
    //printf("coin.%s (%s)\n",coin->name,coinaddr);
    if ( (privkey = dumpprivkey(coin->name,coin->serverport,coin->userpass,coinaddr)) != 0 )
    {
        //printf("privkey.(%s)\n",privkey);
        key = calloc(1,sizeof(*key));
        if ( key != 0 && btc_setprivkey(key,privkey) == 0 && btc_getpubkey(pubP,buf,key) > 0 )
            return(key);
        btc_freekey(key);
    }
    return(0);
}

void set_spendscript(char *spendscript,char *coinaddr)
{
    char hexaddr[128];
    btc_convaddr(hexaddr,coinaddr);
    sprintf(spendscript,"76a914%s88ac",hexaddr+2);
}

int32_t script_coinaddr(char *coinaddr,cJSON *scriptobj)
{
    struct destbuf buf; cJSON *addresses;
    coinaddr[0] = 0;
    if ( scriptobj == 0 )
        return(-1);
    if ( (addresses= cJSON_GetObjectItem(scriptobj,"addresses")) != 0 )
    {
        copy_cJSON(&buf,jitem(addresses,0));
        strcpy(coinaddr,buf.buf);
        return(0);
    }
    return(-1);
}

char *pangea_signp2sh(int32_t oldtx_format,struct cointx_info *refT,int32_t redeemi,char *redeemscript,char sigs[][256],int32_t n,uint8_t privkey[32],int32_t privkeyind)
{
    char hexstr[16384]; bits256 hash2; uint8_t data[4096],sigbuf[512]; struct bp_key key;
    struct cointx_info *T; int32_t i,len; void *sig = NULL; size_t siglen = 0; struct cointx_input *vin;
    if ( bp_key_init(&key) != 0 && bp_key_secret_set(&key,privkey,32) != 0 )
    {
        if ( (T= calloc(1,sizeof(*T))) == 0 )
            return(0);
        *T = *refT; vin = &T->inputs[redeemi];
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
    }
    return(0);
}

uint64_t jumblr_getcoinaddr(char *coinaddr,struct destbuf *scriptPubKey,struct coin777 *coin,char *txid,int32_t vout)
{
    char *rawtransaction,*txidstr,*asmstr; uint64_t value = 0; int32_t n,m,len,reqSigs; cJSON *json,*scriptobj,*array,*item,*hexobj;
    scriptPubKey->buf[0] = 0;
    if ( (rawtransaction= _get_transaction(coin->name,coin->serverport,coin->userpass,txid)) == 0 )
    {
        printf("jumblr_getprivkey: error getting (%s)\n",txid);
        return(0);
    }
    if ( (json= cJSON_Parse(rawtransaction)) != 0 )
    {
        if ( (txidstr= jstr(json,"txid")) == 0 || strcmp(txidstr,txid) != 0 )
        {
            printf("jumblr_getcoinaddr no txid or mismatch\n");
            free_json(json);
            free(rawtransaction);
            return(0);
        }
        if ( (array= jarray(&n,json,"vout")) != 0 && vout < n && (item= jitem(array,vout)) != 0 )
        {
            reqSigs = (int32_t)get_cJSON_int(item,"reqSigs");
            value = conv_cJSON_float(item,"value");
            scriptobj = cJSON_GetObjectItem(item,"scriptPubKey");
            printf("ITEM.(%s)\n",jprint(item,0));
            if ( scriptobj != 0 )
            {
                printf("script.(%s)\n",jprint(scriptobj,0));
                script_coinaddr(coinaddr,scriptobj);
                hexobj = cJSON_GetObjectItem(scriptobj,"hex");
                if ( scriptPubKey != 0 && hexobj != 0 )
                    copy_cJSON(scriptPubKey,hexobj);
                else
                {
                    // OP_DUP OP_HASH160 f563e867027dedd109c9bb5f3354c3cc41dc7c7f OP_EQUALVERIFY OP_CHECKSIG
                    // 0318d4f6cdcbe6c822b979fc318dbe4ad58287223c8fb57b7bec0c88cd58a4b16a OP_CHECKSIG
                    if ( (asmstr= jstr(scriptobj,"asm")) != 0 )
                    {
                        len = (int32_t)strlen(asmstr);
                        m = (int32_t)strlen(" OP_EQUALVERIFY OP_CHECKSIG");
                        if ( strncmp(asmstr,"OP_DUP OP_HASH160 ",strlen("OP_DUP OP_HASH160 ")) == 0 && strcmp(&asmstr[len - m]," OP_EQUALVERIFY OP_CHECKSIG") == 0 )
                            set_spendscript(scriptPubKey->buf,coinaddr);
                        else
                        {
                            printf("nonstandard.(%s)\n",&asmstr[len - m]);
                            m = (int32_t)strlen(" OP_CHECKSIG");
                            if ( strcmp(&asmstr[len - m]," OP_CHECKSIG") == 0 )
                            {
                                printf("key sig (%s)\n",asmstr);
                                sprintf(scriptPubKey->buf,"%02x",(len-m)/2);
                                memcpy(&scriptPubKey->buf[2],asmstr,(len - m));
                                scriptPubKey->buf[2 + (len - m)] = 0;
                                strcat(scriptPubKey->buf,"ac");
                            }
                        }
                    }
                }
            } else printf("null scriptobj.%p (%s)\n",scriptobj,coinaddr);
        }
        free_json(json);
    }
    free(rawtransaction);
    return(value);
}

char *jumblr_getprivkey(uint64_t *valuep,struct destbuf *scriptPubKey,uint32_t *locktimep,struct coin777 *coin,char *txid,int32_t vout)
{
    char *rawtransaction,*txidstr,*privkey=0,coinaddr[64]; uint64_t value = 0; int32_t n,reqSigs; cJSON *json,*scriptobj,*array,*item,*hexobj;
    *locktimep = -1;
    scriptPubKey->buf[0] = 0;
    if ( (rawtransaction= _get_transaction(coin->name,coin->serverport,coin->userpass,txid)) == 0 )
    {
        printf("jumblr_getprivkey: error getting (%s)\n",txid);
        return(0);
    }
    if ( (json= cJSON_Parse(rawtransaction)) != 0 )//get_decoderaw_json(coin,rawtransaction)) != 0 )
    {
        *locktimep = (int32_t)get_cJSON_int(json,"locktime");
        if ( (txidstr= jstr(json,"txid")) == 0 || strcmp(txidstr,txid) != 0 )
        {
            printf("jumblr_getprivkey no txid or mismatch\n");
            free_json(json);
            free(rawtransaction);
            return(0);
        }
        //printf("txidstr.(%s) vout.%d\n",txidstr,vout);
        if ( (array= jarray(&n,json,"vout")) != 0 && (item= jitem(array,vout)) != 0 )
        {
            scriptobj = cJSON_GetObjectItem(item,"scriptPubKey");
            if ( scriptobj != 0 && script_coinaddr(coinaddr,scriptobj) == 0 )
            {
                reqSigs = (int32_t)get_cJSON_int(item,"reqSigs");
                value = conv_cJSON_float(item,"value");
                hexobj = cJSON_GetObjectItem(scriptobj,"hex");
                if ( scriptPubKey != 0 && hexobj != 0 )
                    copy_cJSON(scriptPubKey,hexobj);
                privkey = dumpprivkey(coin->name,coin->serverport,coin->userpass,coinaddr);
            } else printf("null scriptobj.%p (%s)\n",scriptobj,coinaddr);
        }
        free_json(json);
    }
    free(rawtransaction);
    if ( valuep != 0 )
        *valuep = value;
    return(privkey);
}

cJSON *cointx_vins_json_params(struct coin777 *coin,char *rawbytes)
{
    int32_t i; cJSON *json,*array; char coinaddr[128]; struct destbuf scriptPubKey; struct cointx_info *cointx;
    array = cJSON_CreateArray();
    printf("convert.(%s)\n",rawbytes);
    if ( (cointx= _decode_rawtransaction(rawbytes,coin->mgw.oldtx_format)) != 0 )
    {
        disp_cointx(cointx);
        for (i=0; i<cointx->numinputs; i++)
        {
            json = cJSON_CreateObject();
            jaddstr(json,"txid",cointx->inputs[i].tx.txidstr);
            jaddnum(json,"vout",cointx->inputs[i].tx.vout);
            if ( cointx->inputs[i].sigs[0] != 0 )
                jaddstr(json,"scriptPubKey",cointx->inputs[i].sigs);
            else
            {
                jumblr_getcoinaddr(coinaddr,&scriptPubKey,coin,cointx->inputs[i].tx.txidstr,cointx->inputs[i].tx.vout);
                jaddstr(json,"scriptPubKey",scriptPubKey.buf);
            }
            cJSON_AddItemToArray(array,json);
        }
        free(cointx);
    }
    return(array);
}

char *jumblr_signraw_json_params(struct coin777 *coin,char *rawbytes)
{
    char *paramstr = 0; cJSON *array,*rawobj,*vinsobj;//,*keysobj;char *coinaddrs[MAX_SUBATOMIC_INPUTS+1],
    if ( (rawobj= cJSON_CreateString(rawbytes)) != 0 )
    {
        if ( (vinsobj= cointx_vins_json_params(coin,rawbytes)) != 0 )
        {
            array = cJSON_CreateArray();
            jaddi(array,rawobj);
            jaddi(array,vinsobj);
            //cJSON_AddItemToArray(array,keysobj);
            paramstr = jprint(array,1);
        }
        else free_json(rawobj);
    }
    return(paramstr);
}

int32_t jumblr_signtx(char *signedtx,unsigned long destsize,struct coin777 *coin,char *signparams)
{
    cJSON *json,*compobj; char *retstr,*deststr; uint32_t completed = 0;
    signedtx[0] = 0;
    //printf("cp.%d vs %d: subatomic_signtx rawbytes.(%s)\n",cp->coinid,coinid,rawbytes);
    if ( coin != 0 && signparams != 0 )
    {
        _stripwhite(signparams,' ');
        printf("got signparams.(%s)\n",signparams);
        if ( (retstr= bitcoind_RPC(0,coin->name,coin->serverport,coin->userpass,"signrawtransaction",signparams)) != 0 )
        {
            //printf("got retstr.(%s)\n",retstr);
            if ( (json= cJSON_Parse(retstr)) != 0 )
            {
                if ( (deststr= jstr(json,"hex")) != 0 )
                {
                    compobj = cJSON_GetObjectItem(json,"complete");
                    if ( compobj != 0 )
                        completed = ((compobj->type&0xff) == cJSON_True);
                    if ( strlen(deststr) > destsize )
                        printf("sign_rawtransaction: strlen(deststr) %ld > %ld destize\n",(long)strlen(deststr),destsize);
                    else strcpy(signedtx,deststr);
                } else printf("cant get hex from.(%s)\n",retstr);
                free_json(json);
            } else printf("json parse error.(%s)\n",retstr);
            free(retstr);
        } else printf("error signing rawtx\n");
    } else printf("error generating signparams\n");
    return(completed);
}

char *jumblr_signvin(char *sigstr,struct coin777 *coin,char *signedtx,int32_t bufsize,void *bpkey,char *pubP,struct cointx_info *refT,int32_t redeemi,char *rawtx)
{
    // signrawtransaction <hex string> [{"txid":txid,"vout":n,"scriptPubKey":hex},...] [<privatekey1>,...]
    char hexstr[4096],redeem[2048]; bits256 hash2; uint8_t *data,sigbuf[1024];
    struct cointx_info *T; int32_t i; void *sig = NULL; size_t siglen = 0; struct cointx_input *vin;
    sigstr[0] = 0;
    if ( 1 )
    {
        char *paramstr; cJSON *vinarray,*item,*array = cJSON_CreateArray();
        vinarray = cJSON_CreateArray();
        jaddistr(array,rawtx);
        for (i=0; i<refT->numinputs; i++)
        {
            vin = &refT->inputs[i];
            item = cJSON_CreateObject();
            jaddstr(item,"txid",vin->tx.txidstr);
            jaddnum(item,"vout",vin->tx.vout);
            jaddstr(item,"scriptPubKey",vin->sigs);
            jaddi(vinarray,item);
        }
        jaddi(array,vinarray);
        paramstr = jprint(array,1);
        if ( jumblr_signtx(signedtx,bufsize,coin,paramstr) > 0 )
            printf("SIGS completed\n");
        if ( signedtx[0] != 0 )
        {
            if ( (T= _decode_rawtransaction(signedtx,coin->mgw.oldtx_format)) != 0 )
            {
                strcpy(sigstr,T->inputs[redeemi].sigs);
                free(T);
                return(sigstr);
            }
        }
        return(0);
    }
    if ( (T = calloc(1,sizeof(*T))) == 0 )
    {
        printf("unexpected out of mem in jumblr_signvin\n");
        return(0);
    }
    
    *T = *refT;
    vin = &T->inputs[redeemi];
    safecopy(redeem,vin->sigs,sizeof(redeem));
    fprintf(stderr,"redeemi.%d numinputs.%d\n",redeemi,T->numinputs);
    for (i=0; i<T->numinputs; i++)
        if ( i != redeemi )
            strcpy(T->inputs[i].sigs,"00");
    vin->sequence = (uint32_t)-1;
    T->nlocktime = 0;
    data = malloc(65536);
    disp_cointx(T);
    emit_cointx(&hash2,data,sizeof(data),T,coin->mgw.oldtx_format,SIGHASH_ALL);
    free(data);
    if ( bp_sign(bpkey,hash2.bytes,sizeof(hash2),&sig,&siglen) != 0 && sig != 0 )
    {
        memcpy(sigbuf,sig,siglen);
        free(sig);
        sigbuf[siglen++] = SIGHASH_ALL;
        init_hexbytes_noT(hexstr,sigbuf,(int32_t)siglen);
        sprintf(vin->sigs,"%02x%s%02x%s",(uint32_t)siglen,hexstr,(uint32_t)strlen(pubP)/2,pubP);
        strcpy(sigstr,vin->sigs);
        printf("after P.(%s) siglen.%02x -> %s pubP.(%s)\n",sigstr,(uint32_t)siglen,vin->sigs,pubP);
    }
    free(T);
    if ( sigstr[0] != 0 )
        return(sigstr);
    else return(0);
}

int32_t script_has_coinaddr(cJSON *scriptobj,char *coinaddr)
{
    int32_t i,n; struct destbuf buf; cJSON *addresses,*addrobj;
    if ( scriptobj == 0 )
        return(0);
    addresses = cJSON_GetObjectItem(scriptobj,"addresses");
    if ( addresses != 0 )
    {
        n = cJSON_GetArraySize(addresses);
        for (i=0; i<n; i++)
        {
            addrobj = cJSON_GetArrayItem(addresses,i);
            copy_cJSON(&buf,addrobj);
            if ( strcmp(buf.buf,coinaddr) == 0 )
                return(1);
        }
    }
    return(0);
}

cJSON *get_decoderaw_json(struct coin777 *coin,char *rawtransaction)
{
    char *str,*retstr; cJSON *json = 0;
    str = malloc(strlen(rawtransaction)+4);
    //printf("got rawtransaction.(%s)\n",rawtransaction);
    sprintf(str,"\"%s\"",rawtransaction);
    if ( (retstr= bitcoind_passthru(coin->name,coin->serverport,coin->userpass,"decoderawtransaction",str)) != 0 && retstr[0] != 0 )
    {
        //printf("got decodetransaction.(%s)\n",retstr);
        json = cJSON_Parse(retstr);
    } else printf("error decoding.(%s)\n",str);
    if ( retstr != 0 )
        free(retstr);
    free(str);
    return(json);
}

char *subatomic_decodetxid(int64_t *valuep,struct destbuf *scriptPubKey,uint32_t *locktimep,struct coin777 *coin,char *rawtransaction,char *mycoinaddr)
{
    char *txidstr,checkasmstr[1024],*asmstr,*txid = 0; uint64_t value = 0; int32_t i,n,nval,reqSigs; cJSON *json,*scriptobj,*array,*item,*hexobj;
    *locktimep = -1;
    if ( (json= get_decoderaw_json(coin,rawtransaction)) != 0 )
    {
        *locktimep = (int32_t)get_cJSON_int(json,"locktime");
        if ( (txidstr= jstr(json,"txid")) == 0 )
        {
            printf("subatomic_decodetxid no txid\n");
            return(0);
        }
        txid = clonestr(txidstr);
        array = cJSON_GetObjectItem(json,"vout");
        if ( mycoinaddr != 0 && is_cJSON_Array(array) != 0 )
        {
            n = cJSON_GetArraySize(array);
            for (i=0; i<n; i++)
            {
                item = cJSON_GetArrayItem(array,i);
                hexobj = 0;
                scriptobj = cJSON_GetObjectItem(item,"scriptPubKey");
                if ( mycoinaddr != 0 && scriptobj != 0 && script_has_coinaddr(scriptobj,mycoinaddr) != 0 )
                {
                    nval = (int32_t)get_cJSON_int(item,"n");
                    if ( nval == i )
                    {
                        reqSigs = (int32_t)get_cJSON_int(item,"reqSigs");
                        value = conv_cJSON_float(item,"value");
                        hexobj = cJSON_GetObjectItem(scriptobj,"hex");
                        if ( scriptPubKey != 0 && hexobj != 0 )
                            copy_cJSON(scriptPubKey,hexobj);
                        if ( reqSigs == 1 && hexobj != 0 )
                        {
                            sprintf(checkasmstr,"OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG","need to figure out how ot gen magic number");
                            if ( (asmstr= jstr(scriptobj,"asm")) != 0 && strcmp(asmstr,checkasmstr) != 0 )
                                printf("warning: (%s) != check.(%s)\n",asmstr,checkasmstr);
                        }
                    }
                }
            }
        }
    }
    if ( valuep != 0 )
        *valuep = value;
    return(txid);
}

cJSON *subatomic_vins_json_params(struct coin777 *coin,struct subatomic_rawtransaction *rp)
{
    int32_t i; cJSON *json,*array; struct subatomic_unspent_tx *up;
    array = cJSON_CreateArray();
    for (i=0; i<rp->numinputs; i++)
    {
        up = &rp->inputs[i];
        json = cJSON_CreateObject();
        jaddstr(json,"txid",up->txid.buf);
        jaddnum(json,"vout",up->vout);
        if ( up->scriptPubKey.buf[0] != 0 )
            jaddstr(json,"scriptPubKey",up->scriptPubKey.buf);
        if ( up->redeemScript.buf[0] != 0 )
            jaddstr(json,"redeemScript",up->redeemScript.buf);
        cJSON_AddItemToArray(array,json);
    }
    return(array);
}

cJSON *subatomic_privkeys_json_params(struct coin777 *coin,char **coinaddrs,int32_t n)
{
    int32_t i; char *privkey; cJSON *array = cJSON_CreateArray();
    //sprintf(walletkey,"[\"%s\",%d]",Global_subatomic->NXTADDR,BITCOIN_WALLET_UNLOCKSECONDS);
    // locking first avoids error, hacky but no time for wallet fiddling now
    //bitcoind_RPC(0,coin->name,coin->serverport,coin->userpass,"walletlock",0);
    //bitcoind_RPC(0,coin->name,coin->serverport,coin->userpass,"walletpassphrase",walletkey);
    for (i=0; i<n; i++)
    {
        if ( coinaddrs[i][0] != 0 )
        {
            printf("privkeys.(%s)\n",coinaddrs[i]);
            if ( (privkey= dumpprivkey(coin->name,coin->serverport,coin->userpass,coinaddrs[i])) != 0 )
            {
                jaddistr(array,privkey);
                free(privkey);
            }
        }
    }
    return(array);
}

char *subatomic_signraw_json_params(char *skipaddr,char *coinaddr,struct coin777 *coin,struct subatomic_rawtransaction *rp,char *rawbytes)
{
    int32_t i,j,flag; char *coinaddrs[MAX_SUBATOMIC_INPUTS+1],*paramstr = 0; cJSON *array,*rawobj,*vinsobj,*keysobj;
    if ( (rawobj= cJSON_CreateString(rawbytes)) != 0 )
    {
        if ( (vinsobj= subatomic_vins_json_params(coin,rp)) != 0 )
        {
            // printf("add %d inputs skipaddr.%s coinaddr.%s\n",rp->numinputs,skipaddr,coinaddr);
            for (i=flag=j=0; i<rp->numinputs; i++)
            {
                if ( skipaddr == 0 || strcmp(rp->inputs[i].address.buf,skipaddr) != 0 )
                {
                    printf("i.%d j.%d flag.%d %s\n",i,j,flag,rp->inputs[i].address.buf);
                    coinaddrs[j] = rp->inputs[i].address.buf;
                    if ( coinaddr != 0 && strcmp(coinaddrs[j],coinaddr) == 0 )
                        flag++;
                    j++;
                }
            }
            //printf("i.%d j.%d flag.%d\n",i,j,flag);
            //if ( coinaddr != 0 && flag == 0 )
            //coinaddrs[j++] = coinaddr;
            coinaddrs[j] = 0;
            keysobj = subatomic_privkeys_json_params(coin,coinaddrs,j);
            if ( keysobj != 0 )
            {
                array = cJSON_CreateArray();
                cJSON_AddItemToArray(array,rawobj);
                cJSON_AddItemToArray(array,vinsobj);
                cJSON_AddItemToArray(array,keysobj);
                paramstr = cJSON_Print(array);
                free_json(array);
            }
            else free_json(vinsobj);
        }
        else free_json(rawobj);
    }
    return(paramstr);
}

char *subatomic_signtx(char *skipaddr,uint32_t *lockedblockp,int64_t *valuep,char *coinaddr,char *signedtx,unsigned long destsize,struct coin777 *coin,struct subatomic_rawtransaction *rp,char *rawbytes)
{
    cJSON *json,*compobj; char *retstr,*deststr,*signparams,*txid = 0; uint32_t locktime = 0;
    rp->txid[0] = signedtx[0] = 0;
    rp->completed = -1;
    //printf("cp.%d vs %d: subatomic_signtx rawbytes.(%s)\n",cp->coinid,coinid,rawbytes);
    if ( coin != 0 && (signparams= subatomic_signraw_json_params(skipaddr,coinaddr,coin,rp,rawbytes)) != 0 )
    {
        _stripwhite(signparams,' ');
        //printf("got signparams.(%s)\n",signparams);
        if ( (retstr= bitcoind_RPC(0,coin->name,coin->serverport,coin->userpass,"signrawtransaction",signparams)) != 0 )
        {
            //printf("got retstr.(%s)\n",retstr);
            if ( (json= cJSON_Parse(retstr)) != 0 )
            {
                if ( (deststr= jstr(json,"hex")) != 0 )
                {
                    compobj = cJSON_GetObjectItem(json,"complete");
                    if ( compobj != 0 )
                        rp->completed = ((compobj->type&0xff) == cJSON_True);
                    if ( strlen(deststr) > destsize )
                        printf("sign_rawtransaction: strlen(deststr) %ld > %ld destize\n",(long)strlen(deststr),destsize);
                    else
                    {
                        strcpy(signedtx,deststr);
                        txid = subatomic_decodetxid(valuep,0,&locktime,coin,deststr,coinaddr);
                        if ( txid != 0 )
                        {
                            safecopy(rp->txid,txid,sizeof(rp->txid));
                            free(txid);
                            txid = rp->txid;
                        }
                        // printf("got signedtransaction -> txid.(%s) %.8f\n",rp->txid,dstr(valuep!=0?*valuep:0));
                    }
                } else printf("cant get hex from.(%s)\n",retstr);
                free_json(json);
            } else printf("json parse error.(%s)\n",retstr);
            free(retstr);
        } else printf("error signing rawtx\n");
        free(signparams);
    } else printf("error generating signparams\n");
    if ( lockedblockp != 0 )
        *lockedblockp = locktime;
    return(txid);
}

cJSON *subatomic_vouts_json_params(struct subatomic_rawtransaction *rp)
{
    int32_t i; cJSON *json,*obj;
    json = cJSON_CreateObject();
    for (i=0; i<rp->numoutputs; i++)
    {
        obj = cJSON_CreateNumber((double)rp->destamounts[i]/SATOSHIDEN);
        cJSON_AddItemToObject(json,rp->destaddrs[i],obj);
    }
    // printf("numdests.%d (%s)\n",rp->numoutputs,cJSON_Print(json));
    return(json);
}

char *subatomic_rawtxid_json(struct coin777 *coin,struct subatomic_rawtransaction *rp)
{
    char *paramstr = 0; cJSON *array,*vinsobj,*voutsobj;
    if ( (vinsobj= subatomic_vins_json_params(coin,rp)) != 0 )
    {
        if ( (voutsobj= subatomic_vouts_json_params(rp)) != 0 )
        {
            array = cJSON_CreateArray();
            cJSON_AddItemToArray(array,vinsobj);
            cJSON_AddItemToArray(array,voutsobj);
            paramstr = cJSON_Print(array);
            free_json(array);   // this frees both vinsobj and voutsobj
        }
        else free_json(vinsobj);
    }
    // printf("subatomic_rawtxid_json.%s\n",paramstr);
    return(paramstr);
}

uint64_t subatomic_donation(struct coin777 *coin,uint64_t amount)
{
    uint64_t donation = 0;
    if ( coin->donationaddress[0] != 0 )
    {
        donation = amount >> 11;
        if ( donation < coin->mgw.txfee )
            donation = coin->mgw.txfee;
    }
    return(donation);
}

char *gather_account_addresses(struct coin777 *coin,char *account)
{
    cJSON *array,*retarray,*subarray,*item; int32_t i,j,m,n; char *acct;
    //printf("call listaddressgroupings\n");
    if ( (array= _get_localaddresses(coin->name,coin->serverport,coin->userpass)) != 0 )
    {
        retarray = cJSON_CreateArray();
        n = cJSON_GetArraySize(array);
        for (i=0; i<n; i++)
        {
            if ( (subarray= jitem(array,i)) != 0 )
            {
                //printf("%d of %d: %s\n",i,n,jprint(subarray,0));
                if ( is_cJSON_Array(subarray) != 0 && (m= cJSON_GetArraySize(subarray)) > 0 )
                {
                    for (j=0; j<m; j++)
                    {
                        if ( (item= jitem(subarray,j)) != 0 && is_cJSON_Array(item) != 0 && cJSON_GetArraySize(item) > 2 )
                        {
                            if ( (acct= jstr(jitem(item,2),0)) != 0 && strcmp(acct,account) == 0 )
                            {
                                //printf("gather.(%s) %s\n",jstr(jitem(item,0),0),account);
                                jaddistr(retarray,jstr(jitem(item,0),0));
                            }
                        } //else printf("skip item.%p, %d %d\n",item,is_cJSON_Array(item),cJSON_GetArraySize(item));
                    }
                }
            }
        }
        free_json(array);
        if ( cJSON_GetArraySize(retarray) == 0 )
        {
            free_json(retarray);
            return(0);
        }
        else return(jprint(retarray,1));
    }
    else return(0);
}

struct subatomic_unspent_tx *gather_unspents(uint64_t *totalp,int32_t *nump,struct coin777 *coin,char *account)
{
    int32_t i,j,num; struct subatomic_unspent_tx *ups = 0; char *params,*addrs,*retstr; cJSON *json,*item;
    /*{
     "txid" : "1ccd2a9d0f8d690ed13b6768fc6c041972362f5531922b6b152ed2c98d3fe113",
     "vout" : 1,
     "address" : "DK3nxu6GshBcQNDMqc66ARcwqDZ1B5TJe5",
     "scriptPubKey" : "76a9149891029995222077889b36c77e2b85690878df9088ac",
     "amount" : 2.00000000,
     "confirmations" : 72505
     },*/
    *totalp = *nump = 0;
    if ( account != 0 && account[0] != 0 )
    {
        if ( (addrs= gather_account_addresses(coin,account)) != 0 )
        {
            if ( (params = calloc(1,strlen(addrs) + 128)) == 0 )
            {
                free(addrs);
                return(0);
            }
            addrs[strlen(addrs)-1] = 0;
            sprintf(params,"[%d, 99999999, [%s]]",coin->minconfirms,addrs+1);
            free(addrs);
        } else return(0);
    }
    else
    {
        if ( (params = calloc(1,128)) == 0 )
            return(0);
        sprintf(params,"%d, 99999999",coin->minconfirms);
    }
    //printf("issue listunspent.(%s)\n",params);
    if ( (retstr= bitcoind_passthru(coin->name,coin->serverport,coin->userpass,"listunspent",params)) != 0 )
    {
        //printf("unspents (%s)\n",retstr);
        if ( (json= cJSON_Parse(retstr)) != 0 )
        {
            if ( is_cJSON_Array(json) != 0 && (num= cJSON_GetArraySize(json)) > 0 )
            {
                ups = calloc(num,sizeof(struct subatomic_unspent_tx));
                for (i=j=0; i<num; i++)
                {
                    item = cJSON_GetArrayItem(json,i);
                    copy_cJSON(&ups[j].address,cJSON_GetObjectItem(item,"address"));
                    //if ( skipcoinaddr == 0 || strcmp(skipcoinaddr,ups[j].address.buf) != 0 )
                    {
                        copy_cJSON(&ups[j].txid,cJSON_GetObjectItem(item,"txid"));
                        copy_cJSON(&ups[j].scriptPubKey,cJSON_GetObjectItem(item,"scriptPubKey"));
                        ups[j].vout = (int32_t)get_cJSON_int(item,"vout");
                        ups[j].amount = conv_cJSON_float(item,"amount");
                        ups[j].confirmations = (int32_t)get_cJSON_int(item,"confirmations");
                        *totalp += ups[j].amount;
                        j++;
                    }
                }
                *nump = j;
                if ( j > 0 )
                {
                    int _decreasing_signedint64(const void *a,const void *b);
                    if ( j > 1 )
                        qsort(ups,j,sizeof(*ups),_decreasing_signedint64);
                    if ( coin->changeaddr[0] == 0 )
                        strcpy(coin->changeaddr,ups[0].address.buf);
                    //for (i=0; i<j; i++)
                    //printf("%s/v%-3d %13.6f %s confs.%-6d | total %.6f\n",ups[i].txid.buf,ups[i].vout,dstr(ups[i].amount),ups[i].address.buf,ups[i].confirmations,dstr(*totalp));
                }
            }
            free_json(json);
        }
        free(retstr);
    }
    free(params);
    if ( *nump == 0 )
        printf("no (%s) unspents for (%s)\n",coin->name,account != 0 ? account : "");
    return(ups);
}

struct subatomic_unspent_tx *subatomic_bestfit(struct coin777 *coin,struct subatomic_unspent_tx *unspents,int32_t numunspents,uint64_t value,int32_t mode)
{
    int32_t i; uint64_t above,below,gap,atx_value; struct subatomic_unspent_tx *vin,*abovevin,*belowvin;
    abovevin = belowvin = 0;
    for (above=below=i=0; i<numunspents; i++)
    {
        vin = &unspents[i];
        atx_value = vin->amount;
        //printf("(%.8f vs %.8f)\n",dstr(atx_value),dstr(value));
        if ( atx_value == value )
            return(vin);
        else if ( atx_value > value )
        {
            gap = (atx_value - value);
            if ( above == 0 || gap < above )
            {
                above = gap;
                abovevin = vin;
            }
        }
        else if ( mode == 0 )
        {
            gap = (value - atx_value);
            if ( below == 0 || gap < below )
            {
                below = gap;
                belowvin = vin;
            }
        }
    }
    if ( (vin= (abovevin != 0) ? abovevin : belowvin) == 0 && mode == 1 )
        vin = unspents;
    return(vin);
}

int64_t subatomic_calc_rawinputs(struct coin777 *coin,struct subatomic_rawtransaction *rp,uint64_t amount,struct subatomic_unspent_tx *ups,int32_t num,uint64_t donation)
{
    uint64_t sum = 0; struct subatomic_unspent_tx *up; int32_t i;
    rp->inputsum = rp->numinputs = 0;
    printf("unspent num %d, amount %.8f vs donation %.8f txfee %.8f\n",num,dstr(amount),dstr(donation),dstr(coin->mgw.txfee));
    if ( coin == 0 || num == 0 ) // (donation + coin->mgw.txfee) > amount ||
        return(0);
    amount += coin->mgw.txfee + donation;
    for (i=0; i<num&&i<((int32_t)(sizeof(rp->inputs)/sizeof(*rp->inputs))); i++)
    {
        if ( (up= subatomic_bestfit(coin,ups,num,amount,0)) != 0 )
        {
            sum += up->amount;
            rp->inputs[rp->numinputs++] = *up;
            if ( sum >= amount )
            {
                rp->amount = (amount - coin->mgw.txfee - donation);
                rp->change = (sum - amount);
                rp->inputsum = sum;
                printf("numinputs %d sum %.8f vs amount %.8f change %.8f -> txfee %.8f\n",rp->numinputs,dstr(rp->inputsum),dstr(amount),dstr(rp->change),dstr(sum - rp->change - rp->amount));
                return(rp->inputsum);
            }
        }
        printf("error getting bestfit unspent\n");
        break;
    }
    printf("i.%d error numinputs %d sum %.8f\n",i,rp->numinputs,dstr(rp->inputsum));
    return(0);
}

char *subatomic_gen_rawtransaction(char *skipaddr,struct coin777 *coin,struct subatomic_rawtransaction *rp,char *signcoinaddr,uint32_t locktime,uint32_t vin0sequenceid,char *redeem0script)
{
    char *rawparams,*retstr,*txid=0; int64_t value; long len; struct cointx_info *cointx;
    if ( (rawparams= subatomic_rawtxid_json(coin,rp)) != 0 )
    {
        _stripwhite(rawparams,' ');
        //printf("create.(%s)\n",rawparams);
        if ( (retstr= bitcoind_RPC(0,coin->name,coin->serverport,coin->userpass,"createrawtransaction",rawparams)) != 0 )
        {
            if ( retstr[0] != 0 )
            {
                // printf("calc_rawtransaction retstr.(%s)\n",retstr);
                safecopy(rp->rawtransaction,retstr,sizeof(rp->rawtransaction));
                len = strlen(rp->rawtransaction);
                if ( len < 8 )
                {
                    printf("funny rawtransactionlen %ld??\n",len);
                    free(rawparams);
                    return(0);
                }
                if ( locktime != 0 || redeem0script != 0 )
                {
                    if ( (cointx= _decode_rawtransaction(rp->rawtransaction,coin->mgw.oldtx_format)) != 0 )
                    {
                        //printf("%s\n->\n",rp->rawtransaction);
                        cointx->nlocktime = locktime;
                        cointx->inputs[0].sequence = vin0sequenceid;
                        if ( redeem0script != 0 )
                            safecopy(cointx->outputs[0].script,redeem0script,sizeof(cointx->outputs[0].script));
                        _emit_cointx(rp->rawtransaction,sizeof(rp->rawtransaction),cointx,coin->mgw.oldtx_format);
                        _validate_decoderawtransaction(rp->rawtransaction,cointx,coin->mgw.oldtx_format);
                        //printf("spliced tx.(%s)\n",rp->rawtransaction);
                        free(cointx);
                    }
                    printf("locktime.%d sequenceid.%d signcoinaddr.(%s)\n",locktime,vin0sequenceid,signcoinaddr!=0?signcoinaddr:"");
                }
                if ( signcoinaddr != 0 )
                {
                    txid = subatomic_signtx(skipaddr,0,&value,signcoinaddr,rp->signedtransaction,sizeof(rp->signedtransaction),coin,rp,rp->rawtransaction);
                    printf("signedtxid.%s\n",txid);
                }
            }
            free(retstr);
        } else printf("error creating rawtransaction from.(%s)\n",rawparams);
        free(rawparams);
    } else printf("error creating rawparams\n");
    return(txid);
}

char *subatomic_signp2sh(char *sigstr,struct coin777 *coin,struct cointx_info *refT,int32_t msigflag,int32_t lockblocks,int32_t redeemi,char *redeemscript,int32_t p2shflag,char *privkeystr,int32_t privkeyind,char *othersig,char *otherpubkey,char *checkprivkey)
{
    char hexstr[1024],pubP[128],*sig0,*sig1; bits256 hash2; uint8_t data[4096],sigbuf[512]; struct bp_key key,keyV;
    struct cointx_info *T; int32_t i,n; void *sig = NULL; size_t siglen = 0; struct cointx_input *vin;
    if ( (T= calloc(1,sizeof(*T))) == 0 )
        return(0);
    if ( privkeystr != 0 )
        btc_setprivkey(&key,privkeystr);
    *T = *refT; vin = &T->inputs[redeemi];
    for (i=0; i<T->numinputs; i++)
        strcpy(T->inputs[i].sigs,"00");
    strcpy(vin->sigs,redeemscript);
    if ( msigflag == 0 )
    {
        vin->sequence = (uint32_t)-1;
        T->nlocktime = 0;
    }
    else
    {
        if ( vin->sequence == 0 )
            vin->sequence = (uint32_t)time(NULL);
        if ( T->nlocktime == 0 && lockblocks != 0 )
        {
            if ( lockblocks != 0 )
            {
                coin->ramchain.RTblocknum = _get_RTheight(&coin->ramchain.lastgetinfo,coin->name,coin->serverport,coin->userpass,coin->ramchain.RTblocknum);
                if ( coin->ramchain.RTblocknum == 0 )
                {
                    printf("cant get RTblocknum for %s\n",coin->name);
                    free(T);
                    return(0);
                }
                lockblocks += coin->ramchain.RTblocknum;
            }
            T->nlocktime = lockblocks;
        }
    }
    //disp_cointx(&T);
    emit_cointx(&hash2,data,sizeof(data),T,coin->mgw.oldtx_format,SIGHASH_ALL);
    //printf("HASH2.(%llx)\n",(long long)hash2.txid);
    if ( msigflag != 0 )
    {
        if ( othersig != 0 )
        {
            n = (int32_t)strlen(otherpubkey) >> 1;
            decode_hex(data,n,otherpubkey);
            if ( bp_key_init(&keyV) == 0 || bp_pubkey_set(&keyV,data,n) == 0 )
            {
                printf("cant set pubkey\n");
                free(T);
                return(0);
            }
            n = (int32_t)strlen(othersig) >> 1;
            decode_hex(data,n,othersig);
            if ( data[n-1] != SIGHASH_ALL )
            {
                printf("othersig.(%s) hash type mismatch %d != %d\n",othersig,data[n-1],SIGHASH_ALL);
                free(T);
                return(0);
            }
            if ( bp_verify(&keyV,hash2.bytes,sizeof(hash2),data,n-1) == 0 )
            {
                hexstr[0] = 0;
                if ( checkprivkey != 0 )
                {
                    //printf("checkprivkey.(%s)\n",checkprivkey);
                    btc_setprivkey(&keyV,checkprivkey);
                    void *dispkey; size_t slen;
                    bp_privkey_get(&keyV,&dispkey,&slen);
                    //for (i=0; i<slen; i++)
                    //    printf("%02x",((uint8_t *)dispkey)[i]);
                    //printf(" checkkey\n");
                    if ( bp_sign(&keyV,hash2.bytes,sizeof(hash2),&sig,&siglen) != 0 )
                        init_hexbytes_noT(hexstr,sigbuf,(int32_t)siglen);
                }
                printf("othersig.(%s) doesnt verify vs (%s)\n",othersig,hexstr);
                //return(0);
            } else printf("SIG.%d VERIFIED\n",privkeyind ^ 1);
        }
        if ( privkeystr != 0 )
        {
            void *dispkey; size_t slen;
            bp_privkey_get(&key,&dispkey,&slen);
            //for (i=0; i<slen; i++)
            //    printf("%02x",((uint8_t *)dispkey)[i]);
            //printf(" dispkey.(%s)\n",privkeystr);
            if ( bp_sign(&key,hash2.bytes,sizeof(hash2),&sig,&siglen) != 0 )
            {
                memcpy(sigbuf,sig,siglen);
                sigbuf[siglen++] = SIGHASH_ALL;
                init_hexbytes_noT(hexstr,sigbuf,(int32_t)siglen);
                if ( sigstr != 0 )
                    strcpy(sigstr,hexstr);
                if ( privkeyind == 0 )
                    sig0 = hexstr, sig1 = othersig != 0 ? othersig : "";
                else sig1 = hexstr, sig0 = othersig != 0 ? othersig : "";
                sprintf(vin->sigs,"00%02x%s%02x%s51",(int32_t)strlen(sig0)>>1,sig0,(int32_t)strlen(sig1)>>1,sig1);
                //printf("after A.(%s) othersig.(%s) siglen.%02lx -> (%s)\n",hexstr,othersig != 0 ? othersig : "",siglen,vin->sigs);
            }
            else
            {
                printf("error signing\n");
                free(T);
                return(0);
            }
        }
        else vin->sigs[0] = 0;
    }
    else
    {
        if ( bp_sign(&key,hash2.bytes,sizeof(hash2),&sig,&siglen) != 0 && btc_getpubkey(pubP,data,&key) > 0 )
        {
            memcpy(sigbuf,sig,siglen);
            sigbuf[siglen++] = SIGHASH_ALL;
            init_hexbytes_noT(hexstr,sigbuf,(int32_t)siglen);
            sprintf(vin->sigs,"%02x%s%02x%s00",(int32_t)siglen,hexstr,(int32_t)strlen(pubP)/2,pubP);
            //printf("after P.(%s) siglen.%02lx\n",vin->sigs,siglen);
        }
    }
    if ( vin->sigs[0] != 0 )
    {
        if ( p2shflag != 0 )
            sprintf(&vin->sigs[strlen(vin->sigs)],"4c%02x",(int32_t)strlen(redeemscript)/2);
        sprintf(&vin->sigs[strlen(vin->sigs)],"%s",redeemscript);
    }
    //printf("scriptSig.(%s)\n",vin->sigs);
    _emit_cointx(hexstr,sizeof(hexstr),T,coin->mgw.oldtx_format);
    //disp_cointx(&T);
    free(T);
    return(clonestr(hexstr));
    //printf("T.msigredeem %d -> (%s)\n",msigflag,hexstr);
}

char *subatomic_fundingtx(char *refredeemscript,struct subatomic_rawtransaction *funding,struct coin777 *coin,char *mypubkey,char *otherpubkey,char *pkhash,uint64_t amount,int32_t lockblocks)
{
    char scriptPubKey[128],mycoinaddr[64],p2shaddr[64],sigstr[512],*refundtx=0,*redeemscript,*txid=0; struct subatomic_unspent_tx *utx;
    uint64_t total,donation; int32_t num,n=0,lockblock = 0; struct cointx_info *refT; uint8_t rmd160[20];
    memset(funding,0,sizeof(*funding));
    refredeemscript[0] = 0;
    if ( (redeemscript= create_atomictx_scripts(coin->p2shtype,scriptPubKey,p2shaddr,mypubkey,otherpubkey,pkhash)) != 0 )
    {
        strcpy(refredeemscript,redeemscript);
        if ( btc_coinaddr(mycoinaddr,coin->addrtype,mypubkey) != 0 && (utx= gather_unspents(&total,&num,coin,0)) != 0 )
        {
            donation = subatomic_donation(coin,amount);
            //printf("CREATE FUNDING TX.(%s) [%s %s %s] for %.8f -> %s locktime.%u donation %.8f\n",coin->name,mypubkey,otherpubkey,pkhash,dstr(amount),p2shaddr,lockblock,dstr(donation));
            if ( subatomic_calc_rawinputs(coin,funding,amount,utx,num,donation) >= amount )
            {
                if ( funding->amount == amount && funding->change == (funding->inputsum - amount - coin->mgw.txfee - donation) )
                {
                    safecopy(funding->destaddrs[n],p2shaddr,sizeof(funding->destaddrs[n]));
                    funding->destamounts[n] = amount;
                    n++;
                }
                if ( donation != 0 )
                {
                    if ( coin->donationaddress[0] != 0 )
                    {
                        safecopy(funding->destaddrs[n],coin->donationaddress,sizeof(funding->destaddrs[n]));
                        funding->destamounts[n] = donation;
                        n++;
                    } else funding->change += donation;
                }
                if ( funding->change != 0 )
                {
                    if ( coin->changeaddr[0] == 0 )
                    {
                        printf("no changeaddress for (%s)\n",coin->name);
                        return(0);
                    }
                    safecopy(funding->destaddrs[n],coin->changeaddr,sizeof(funding->destaddrs[n]));
                    funding->destamounts[n] = funding->change;
                    n++;
                }
                funding->numoutputs = n;
                if ( (txid= subatomic_gen_rawtransaction(0,coin,funding,p2shaddr,lockblock,lockblock==0?0xffffffff:(uint32_t)time(NULL),coin->usep2sh!=0?0:redeemscript)) == 0 )
                    printf("error creating tx\n");
                else
                {
                    if ( (refT= calloc(1,sizeof(*refT))) == 0 )
                        return(0);
                    refT->version = 1;
                    refT->timestamp = (uint32_t)time(NULL);
                    strcpy(refT->inputs[0].tx.txidstr,txid);
                    refT->inputs[0].tx.vout = 0;
                    refT->numinputs = 1;
                    strcpy(scriptPubKey,"76a914");
                    calc_OP_HASH160(scriptPubKey+6,rmd160,mypubkey);
                    strcat(scriptPubKey,"88ac");
                    if ( mycoinaddr[0] != 0 )
                    {
                        strcpy(refT->outputs[0].coinaddr,mycoinaddr);
                        strcpy(refT->outputs[0].script,scriptPubKey);
                        refT->outputs[0].value = funding->destamounts[0] - coin->mgw.txfee;
                        refT->numoutputs = 1;
                        if ( lockblocks == 0 )
                            lockblocks = 10;
                        refundtx = subatomic_signp2sh(sigstr,coin,refT,1,lockblocks,0,redeemscript,coin->usep2sh,0,0,0,0,0);
                        free(refT);
                    } else printf("cant get %s addr from (%s)\n",coin->name,mypubkey);
                }
            } else printf("error: probably not enough funds\n");
        } else printf("error: btc_coinaddr.(%s)\n",mycoinaddr);
        free(redeemscript);
    } else printf("subatomic_fundingtx: cant create redeemscript\n");
    return(refundtx);
}

char *subatomic_spendtx(struct destbuf *spendtxid,char *vintxid,char *refundsig,struct coin777 *coin,char *otherpubkey,char *mypubkey,char *onetimepubkey,uint64_t amount,char *refundtx,char *refredeemscript)
{
    char scriptPubKey[128],p2shaddr[64],rmdstr[41],onetimecoinaddr[64],msigcoinaddr[64],sigstr[512]; cJSON *json;
    char *redeemscript,*signedtx,*spendtx=0,*mprivkey,*oprivkey; uint8_t rmd160[20]; long diff=0; struct cointx_info *refundT=0;
    refundsig[0] = onetimecoinaddr[0] = msigcoinaddr[0] = spendtxid->buf[0] = vintxid[0] = 0;
    if ( btc_coinaddr(onetimecoinaddr,coin->addrtype,onetimepubkey) != 0 && btc_coinaddr(msigcoinaddr,coin->addrtype,mypubkey) != 0 )
    {
        //printf("mypubkey.(%s) -> (%s)\n",mypubkey,msigcoinaddr);
        calc_OP_HASH160(rmdstr,rmd160,onetimepubkey);
        amount -= coin->mgw.txfee;
        coin->ramchain.RTblocknum = _get_RTheight(&coin->ramchain.lastgetinfo,coin->name,coin->serverport,coin->userpass,coin->ramchain.RTblocknum);
        if ( (refundT= _decode_rawtransaction(refundtx,coin->mgw.oldtx_format)) != 0 && refundT->inputs[0].sequence != 0xffffffff && refundT->nlocktime != 0 && (diff= ((long)refundT->nlocktime - coin->ramchain.RTblocknum)) > 1 && diff < 1000 )
        {
            strcpy(vintxid,refundT->inputs[0].tx.txidstr);
            if ( (redeemscript= create_atomictx_scripts(coin->p2shtype,scriptPubKey,p2shaddr,otherpubkey,mypubkey,rmdstr)) != 0 )
            {
                if ( refundT->outputs[0].value == amount && strcmp(refredeemscript,redeemscript) == 0 && refundT->numinputs == 1 && refundT->numoutputs == 1 )
                {
                    if ( (mprivkey= dumpprivkey(coin->name,coin->serverport,coin->userpass,msigcoinaddr)) != 0 && (oprivkey= dumpprivkey(coin->name,coin->serverport,coin->userpass,onetimecoinaddr)) != 0 )
                    {
                        //printf("mprivkey.(%s)\n",mprivkey);
                        if ( (signedtx= subatomic_signp2sh(refundsig,coin,refundT,1,0,0,redeemscript,coin->usep2sh,mprivkey,1,0,0,0)) != 0 )
                        {
                            //printf("one sig.(%s)\n",signedtx);
                            free(signedtx);
                            strcpy(refundT->outputs[0].coinaddr,onetimecoinaddr);
                            sprintf(scriptPubKey,"76a914%s88ac",rmdstr);
                            strcpy(refundT->outputs[0].script,scriptPubKey);
                            spendtx = subatomic_signp2sh(sigstr,coin,refundT,0,0,0,redeemscript,coin->usep2sh,oprivkey,0,0,0,0);
                            if ( (json= get_decoderaw_json(coin,spendtx)) != 0 )
                            {
                                copy_cJSON(spendtxid,jobj(json,"txid"));
                                free_json(json);
                            }
                        } else printf("Error signing\n");
                        free(mprivkey);
                        free(oprivkey);
                    }
                    else
                    {
                        if ( mprivkey != 0 )
                            free(mprivkey);
                        printf("error getting privkeys M.(%s) onetime.(%s)\n",msigcoinaddr,onetimecoinaddr);
                    }
                } else printf("error (%.8f vs %.8f) comparing redeemscript.(%s) vs (%s) io.(%d %d)\n",dstr(refundT->outputs[0].value),dstr(amount),refredeemscript,redeemscript,refundT->numinputs,refundT->numoutputs);
                free(redeemscript);
            } else printf("error creating redeemscript\n");
            free(refundT);
        } else printf("error decoding refundT.%p or diff %ld too big (%u %u)\n",refundT,diff,refundT->nlocktime,coin->ramchain.RTblocknum);
    } else printf("error getting addresses (%s) (%s)\n",msigcoinaddr,onetimecoinaddr);
    return(spendtx);
}

char *subatomic_validate(struct coin777 *coin,char *pubA,char *pubB,char *pkhash,char *refundtx,char *refundsig)
{
    char scriptPubKey[512],mycoinaddr[64],p2shaddr[128],mysig[512],*redeemscript,*privkeystr,*signedrefund=0;
    struct cointx_info *refundT;
    if ( (refundT= _decode_rawtransaction(refundtx,coin->mgw.oldtx_format)) != 0 && btc_coinaddr(mycoinaddr,coin->addrtype,pubA) != 0 )
    {
        if ( (privkeystr= dumpprivkey(coin->name,coin->serverport,coin->userpass,mycoinaddr)) != 0 )
        {
            if ( (redeemscript= create_atomictx_scripts(coin->p2shtype,scriptPubKey,p2shaddr,pubA,pubB,pkhash)) != 0 )
            {
                if ( (signedrefund= subatomic_signp2sh(mysig,coin,refundT,1,0,0,redeemscript,1,privkeystr,0,refundsig,pubB,0)) != 0 )
                {
                    //printf("SIGNEDREFUND.(%s)\n",signedrefund);
                }
                free(redeemscript);
            }
            free(privkeystr);
        }
        free(refundT);
    }
    return(signedrefund);
}

void test_subatomic()
{
    char pkhash[8192],pubA[67],pubB[67],pubP[67]; uint8_t tmpbuf[512]; struct coin777 *coin;
    struct subatomic_rawtransaction funding; char refredeemscript[4096],vintxid[128],swapacct[64],othercoinaddr[64],mycoinaddr[64],onetimeaddr[64],refundsig[512],*signedrefund,*refundtx=0,*spendtx=0;
    uint64_t amount; struct destbuf pubkey; struct destbuf spendtxid;
    coin = coin777_find("BTCD",1);
    if ( strcmp(coin->name,"BTC") == 0 )
        coin->mgw.oldtx_format = 1;
    //coin->usep2sh = 0;
    strcpy(mycoinaddr,coin->atomicsend),get_pubkey(&pubkey,coin->name,coin->serverport,coin->userpass,mycoinaddr), strcpy(pubA,pubkey.buf);
    strcpy(othercoinaddr,coin->atomicrecv),get_pubkey(&pubkey,coin->name,coin->serverport,coin->userpass,othercoinaddr), strcpy(pubB,pubkey.buf);
    sprintf(swapacct,"%u",777);
    if ( get_acct_coinaddr(onetimeaddr,coin->name,coin->serverport,coin->userpass,swapacct) != 0 )
    {
        get_pubkey(&pubkey,coin->name,coin->serverport,coin->userpass,onetimeaddr);
        strcpy(pubP,pubkey.buf);
        printf("onetimeadddr.(%s) pubkey.(%s)\n",onetimeaddr,pubP);
    }
    calc_OP_HASH160(pkhash,tmpbuf,pubP);
    amount = 20000;
    printf("pkhash.(%s)\n",pkhash);
    if ( (refundtx= subatomic_fundingtx(refredeemscript,&funding,coin,pubA,pubB,pkhash,20000,10)) != 0 )
    {
        printf("FUNDING.(%s) unsignedrefund.(%s)\n",funding.signedtransaction,refundtx);
        if ( (spendtx= subatomic_spendtx(&spendtxid,vintxid,refundsig,coin,pubA,pubB,pubP,amount,refundtx,refredeemscript)) != 0 )
        {
            printf("vin.%s SPENDTX.(%s) %s refundsig.(%s)\n",vintxid,spendtx,spendtxid.buf,refundsig);
            if ( (signedrefund= subatomic_validate(coin,pubA,pubB,pkhash,refundtx,refundsig)) != 0 )
            {
                printf("SIGNEDREFUND.(%s)\n",signedrefund);
                free(signedrefund);
            } else printf("null signedrefund\n");
        } else printf("null spendtx\n");
        free(refundtx);
    }
    getchar();
}
#endif

#endif
