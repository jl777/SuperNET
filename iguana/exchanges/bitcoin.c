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

//void bu_Hash4(unsigned char *md32,const void *data,size_t data_len);
//cstring *bn_getvch(const BIGNUM *v);

static const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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

char *bitcoin_base58(char *coinaddr,uint8_t *data_,int32_t datalen)
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

char *bitcoin_address(char *coinaddr,uint8_t addrtype,uint8_t pubkey[33])
{
    int32_t i; uint8_t data[25]; bits256 hash; char checkaddr[65];
    vcalc_sha256(0,hash.bytes,pubkey,33);
    calc_rmd160(0,data+1,hash.bytes,sizeof(hash));
    btc_convrmd160(checkaddr,addrtype,data+1);
    data[0] = addrtype;
    hash = bits256_doublesha256(0,data,21);
    for (i=0; i<4; i++)
        data[21+i] = hash.bytes[31-i];
    if ( (coinaddr= bitcoin_base58(coinaddr,data,25)) != 0 )
        printf("checkaddr.(%s) vs coinaddr.(%s)\n",checkaddr,coinaddr);
    return(coinaddr);
}

EC_KEY *bitcoin_key()
{
    return(EC_KEY_new_by_curve_name(NID_secp256k1));
}

void bitcoin_keyfree(EC_KEY *key)
{
	if ( key != 0 )
		EC_KEY_free(key);
}

int32_t bitcoin_pubkeyset(EC_KEY **keyp,uint8_t *pubkey,int32_t pk_len)
{
	//const unsigned char *pubkey = pubkey_;
	if ( o2i_ECPublicKey(keyp,(void *)&pubkey,pk_len) == 0 )
		return(-1);
	if ( pk_len == 33 )
		EC_KEY_set_conv_form(*keyp,POINT_CONVERSION_COMPRESSED), printf("compressed key\n");
	return(0);
}

int32_t bitcoin_verify(EC_KEY *key_,uint8_t *data,int32_t datalen,uint8_t *sig_,int32_t siglen)
{
    int32_t bp_verify(EC_KEY *key, const void *data, size_t data_len,const void *sig_, size_t sig_len);
    int32_t bp_sign(EC_KEY *key, const void *data, size_t data_len,void **sig_, size_t *sig_len_);
    uint8_t newsig[256],*sig = newsig; size_t newlen;
    
    uint8_t pubkey[33]; EC_KEY *key;
    key = bitcoin_key();
    
    decode_hex(pubkey,sizeof(pubkey),"03506a52e95cdfbb9d17d702af6259ba7de8b7a604007999e0266edbf6e4bb6974");
    bitcoin_pubkeyset(&key,pubkey,sizeof(pubkey));
    
    if ( bp_sign(key,data,datalen,(void **)&sig,&newlen) != 0 )
        printf("got new sig\n");
    else printf("sig error\n");
    printf("siglen.%ld\n",newlen);
    if ( bp_verify(key,data,datalen,newsig,newlen) != 0 )
        return(0);
    else return(-1);
	/*const uint8_t *sig = (void *)sig_; ECDSA_SIG *esig; int32_t x,retval = -1;
	if ( (esig= ECDSA_SIG_new()) != 0 )
    {
        if ( d2i_ECDSA_SIG(&esig,&sig,siglen) != 0 )
        {
            if ( (x= ECDSA_do_verify(data,datalen,esig,key)) == 1 )
                retval = 0;
            printf("bitcoin_verify x.%d\n",x);
        }
        ECDSA_SIG_free(esig);
    }
    return(retval);*/
}

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

//{"result":{"txid":"a2b81b9894205ced12dfe276cbe27c05308976b5a2e12789ccd167fe6c3217f7","version":1,"time":1433295027,"locktime":0,"vin":[{"txid":"cf8f5e26e29a74c4fb867338213c02059b975fcfeae993926edbad8aba1cfedb","vout":1,"scriptSig":{"asm":"3045022100f86ab6815d1c22bf9f0fb6c389b558eb644159462054039d393cdba6e480a952022079b7f804c48a0ef5de68bc4be4c18cd5ea947763f4d5f6d415092f8dc00ee1aa01","hex":"483045022100f86ab6815d1c22bf9f0fb6c389b558eb644159462054039d393cdba6e480a952022079b7f804c48a0ef5de68bc4be4c18cd5ea947763f4d5f6d415092f8dc00ee1aa01"},"sequence":4294967295},{"txid":"cfcaef36853be671a5247c1ccb2a54a59d8b4628d0d63726dcdc8dbf73116ae3","vout":2,"scriptSig":{"asm":"3045022100a84f56626e4558e13911290e72d498796ba0bc70a0c9eb59b20d50f6ed94cee30220734c94ab1e89dfe26b3cc1b519a5a6f37863829e9eccdb246843e76577b4040f01","hex":"483045022100a84f56626e4558e13911290e72d498796ba0bc70a0c9eb59b20d50f6ed94cee30220734c94ab1e89dfe26b3cc1b519a5a6f37863829e9eccdb246843e76577b4040f01"},"sequence":4294967295}],"vout":[{"value":0.00000000,"n":0,"scriptPubKey":{"asm":"","type":"nonstandard"}},{"value":1036.57541260,"n":1,"scriptPubKey":{"asm":"03506a52e95cdfbb9d17d702af6259ba7de8b7a604007999e0266edbf6e4bb6974 OP_CHECKSIG","reqSigs":1,"type":"pubkey","addresses":["RJyYWRKSK7cMg5EeW9aHAaT3hHVEkAXnP9"]}}],"blockhash":"6863f2bab8cd9b69dd7a446aa63281f9e5301520f9ba02ca3acc892866872fe4","confirmations":374485},"error":null,"id":"jl777"}

//{"result":{"version":1,"timestamp":1433295027,"vin":[{"sequence":4294967295,"txid":"cf8f5e26e29a74c4fb867338213c02059b975fcfeae993926edbad8aba1cfedb","vout":1,"hex":"483045022100f86ab6815d1c22bf9f0fb6c389b558eb644159462054039d393cdba6e480a952022079b7f804c48a0ef5de68bc4be4c18cd5ea947763f4d5f6d415092f8dc00ee1aa01"}, {"sequence":4294967295,"txid":"cfcaef36853be671a5247c1ccb2a54a59d8b4628d0d63726dcdc8dbf73116ae3","vout":2,"hex":"483045022100a84f56626e4558e13911290e72d498796ba0bc70a0c9eb59b20d50f6ed94cee30220734c94ab1e89dfe26b3cc1b519a5a6f37863829e9eccdb246843e76577b4040f01"}],"numvins":2,"vout":[{"value":0,"n":0,"scriptPubKey":{"asm":"coinbase","addresses":[]}}, {"value":1036.57541260,"n":1,"scriptPubKey":{"asm":"OP_DUP 6a5ad2f911f1bfd7c018c95154e2c049accd04da OP_CHECKSIG","addresses":["RJyYWRKSK7cMg5EeW9aHAaT3hHVEkAXnP9"],"hex":"2103506a52e95cdfbb9d17d702af6259ba7de8b7a604007999e0266edbf6e4bb6974ac"}}],"numvouts":2,"locktime":0,"size":295,"txid":"a2b81b9894205ced12dfe276cbe27c05308976b5a2e12789ccd167fe6c3217f7"},"height":555555,"confirmations":333945,"blockhash":"6863f2bab8cd9b69dd7a446aa63281f9e5301520f9ba02ca3acc892866872fe4","tag":"731886559821890929"}

cJSON *iguana_voutjson(struct iguana_info *coin,struct iguana_msgvout *vout,int32_t txi)
{
    // 035f1321ed17d387e4433b2fa229c53616057964af065f98bfcae2233c5108055e OP_CHECKSIG
    static bits256 zero;
    char scriptstr[8192+1],coinaddr[65],asmstr[16384]; int32_t i,M,N,asmtype;
    uint8_t rmd160[20],msigs160[16][20],addrtype,space[8192];
    cJSON *addrs,*skey,*json = cJSON_CreateObject();
    jaddnum(json,"value",dstr(vout->value));
    jaddnum(json,"n",txi);
    //"scriptPubKey":{"asm":"OP_DUP OP_HASH160 5f69cb73016264270dae9f65c51f60d0e4d6fd44 OP_EQUALVERIFY OP_CHECKSIG","reqSigs":1,"type":"pubkeyhash","addresses":["RHyh1V9syARTf2pyxibz7v27D5paBeWza5"]}
    if ( vout->pk_script != 0 && vout->pk_scriptlen*2+1 < sizeof(scriptstr) )
    {
        if ( (asmtype= iguana_calcrmd160(coin,rmd160,msigs160,&M,&N,vout->pk_script,vout->pk_scriptlen,zero)) >= 0 )
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
        jaddstr(sigjson,"hex",scriptstr);
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
        jaddi(vouts,iguana_voutjson(coin,&vout,i));
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
                jaddi(array,iguana_voutjson(coin,&msg->vouts[i],i));
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

char *iguana_rawtxbytes(struct iguana_info *coin,cJSON *json,uint8_t *data,int32_t datalen)
{
    int32_t n; char *txbytes,vpnstr[64]; struct iguana_msgtx tx;
    vpnstr[0] = 0;
    //char str[65]; printf("%d of %d: %s\n",i,msg.txn_count,bits256_str(str,tx.txid));
    if ( (n= iguana_rwmsgtx(coin,0,json,data,datalen,&tx,&tx.txid,vpnstr)) > 0 )
    {
        txbytes = malloc(n*2+1);
        init_hexbytes_noT(txbytes,data,n);
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

int32_t bitcoin_verifyvins(struct iguana_info *coin,int32_t *scriptlens,struct iguana_msgtx *msgtx,uint8_t *serialized,int32_t maxsize,char *pubkeystr)
{
    char txidstr[128],sigstr[256],coinaddr[64],vpnstr[64]; uint8_t *sig,pubkey[33];
    EC_KEY *key; int32_t n2,i,scriptlen,vini=0,siglen,numvins,hashtype; bits256 txid,sigtxid;
    vpnstr[0] = 0;
    numvins = msgtx->tx_in;
    decode_hex(pubkey,sizeof(pubkey),pubkeystr);
    for (vini=0; vini<numvins; vini++)
    {
        for (i=0; i<numvins; i++)
            msgtx->vins[i].scriptlen = 0;
        i = vini;
        scriptlen = msgtx->vins[i].scriptlen = scriptlens[vini];
        printf("VINI.%d (%s)\n",vini,jprint(bitcoin_txjson(coin,msgtx),1));
        sig = &msgtx->vins[i].script[1];
        siglen = msgtx->vins[i].script[0];
        hashtype = sig[siglen-1];
        bitcoin_address(coinaddr,coin->chain->pubtype,pubkey);
        if ( (key= bitcoin_key()) != 0 )
        {
            if ( bitcoin_pubkeyset(&key,pubkey,33) < 0 )
            {
                printf("cant set pubkey.(%s) %s\n",pubkeystr,coinaddr);
                bitcoin_keyfree(key);
                return(-1);
            }
            printf("vini.%d: scriptlen.%d siglen.%d hashtype.%d coinaddr.%s\n",vini,scriptlen,siglen,hashtype,coinaddr);
        }
        else
        {
            printf("cant get bitcoin_key\n");
            bitcoin_keyfree(key);
            return(-1);
        }
        if ( (n2= iguana_rwmsgtx(coin,1,0,serialized,maxsize,msgtx,&txid,vpnstr)) > 0 )
        {
            n2 += iguana_rwnum(1,&serialized[n2],sizeof(hashtype),&hashtype);
            sigtxid = bits256_doublesha256(txidstr,serialized,n2);
            if ( bitcoin_verify(key,sigtxid.bytes,sizeof(sigtxid),sig,siglen-1) < 0 )
            {
                init_hexbytes_noT(sigstr,sig,siglen);
                printf("othersig.(%s) doesnt verify\n",sigstr);
                bitcoin_keyfree(key);
                return(-1);
            } else printf("SIG.%d VERIFIED\n",vini);
            // 483045022100f86ab6815d1c22bf9f0fb6c389b558eb644159462054039d393cdba6e480a952022079b7f804c48a0ef5de68bc4be4c18cd5ea947763f4d5f6d415092f8dc00ee1aa01
        } else return(-1);
        bitcoin_keyfree(key);
    }
    return(0);
}

int32_t bitcoin_verifytx(struct iguana_info *coin,char *rawtxstr)
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
        if ( bitcoin_verifyvins(coin,scriptlens,&msgtx,serialized2,maxsize,"03506a52e95cdfbb9d17d702af6259ba7de8b7a604007999e0266edbf6e4bb6974") == 0 )
            retval = 0;
        free(scriptlens);
    }
    free(serialized), free(serialized2);
    return(retval);
}

cJSON *bitcoin_txtest(struct iguana_info *coin,char *rawtxstr,bits256 txid)
{
    struct iguana_msgtx msgtx; char str[65],str2[65]; bits256 checktxid,blockhash;
    cJSON *retjson,*txjson; uint8_t *serialized,*serialized2; struct iguana_txid T,*tp;
    char vpnstr[64]; int32_t n,i,*scriptlens,height,n2,maxsize,len = (int32_t)strlen(rawtxstr);
    maxsize = len + 32768;
    serialized = calloc(1,maxsize);
    serialized2 = calloc(1,maxsize);
    len >>= 1;
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
        scriptlens = calloc(msgtx.tx_in,sizeof(*scriptlens));
        for (i=0; i<msgtx.tx_in; i++)
            scriptlens[i] = msgtx.vins[i].scriptlen;
        if ( bitcoin_verifyvins(coin,scriptlens,&msgtx,serialized2,maxsize,"03506a52e95cdfbb9d17d702af6259ba7de8b7a604007999e0266edbf6e4bb6974") < 0 )
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
