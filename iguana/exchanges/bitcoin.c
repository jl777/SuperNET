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
cJSON *instantdex_statemachinejson(struct bitcoin_swapinfo *swap);

char *bitcoind_passthru(char *coinstr,char *serverport,char *userpass,char *method,char *params)
{
    return(bitcoind_RPC(0,coinstr,serverport,userpass,method,params));
}

int32_t bitcoin_pubkeylen(const uint8_t *pubkey)
{
    if ( pubkey[0] == 2 || pubkey[0] == 3 )
        return(33);
    else if ( pubkey[0] == 4 )
        return(65);
    else return(-1);
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
            //char hexaddr[64];
            //btc_convaddr(hexaddr,coinaddr);
            //for (i=0; i<len; i++)
            //    printf("%02x ",buf[i]);
            char str[65]; printf("\nhex checkhash.(%s) len.%d mismatch %02x %02x %02x %02x vs %02x %02x %02x %02x (%s)\n",coinaddr,len,buf[len - 4]&0xff,buf[len - 3]&0xff,buf[len - 2]&0xff,buf[len - 1]&0xff,hash.bytes[31],hash.bytes[30],hash.bytes[29],hash.bytes[28],bits256_str(str,hash));
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
    int32_t i; uint8_t data[25]; bits256 hash;// char checkaddr[65];
    if ( len != 20 )
        calc_rmd160_sha256(data+1,pubkey,len);
    else memcpy(data+1,pubkey,20);
    //btc_convrmd160(checkaddr,addrtype,data+1);
    //for (i=0; i<20; i++)
    //    printf("%02x",data[i+1]);
    //printf(" RMD160 len.%d\n",len);
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

int32_t bitcoin_validaddress(struct iguana_info *coin,char *coinaddr)
{
    uint8_t rmd160[20],addrtype; char checkaddr[128];
    if ( coin == 0 || coinaddr == 0 || coinaddr[0] == 0 )
        return(-1);
    else if ( bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr) < 0 )
        return(-1);
    else if ( addrtype != coin->chain->pubtype && addrtype != coin->chain->p2shtype )
        return(-1);
    else if ( bitcoin_address(checkaddr,addrtype,rmd160,sizeof(rmd160)) != checkaddr || strcmp(checkaddr,coinaddr) != 0 )
        return(-1);
    return(0);
}

int32_t bitcoin_priv2wif(char *wifstr,bits256 privkey,uint8_t addrtype)
{
    uint8_t data[128]; bits256 hash; int32_t i;
    memcpy(data,privkey.bytes,sizeof(privkey));
    data[32] = 1;
    data[0] = addrtype;
    hash = bits256_doublesha256(0,data,33);
    for (i=0; i<4; i++)
        data[33+i] = hash.bytes[31-i];
    if ( bitcoin_base58encode(wifstr,data,33+4) == 0 )
        return(-1);
    char str[65]; printf("(%s) -> wif.(%s) addrtype.%02x\n",bits256_str(str,privkey),wifstr,addrtype);
    return((int32_t)strlen(wifstr));
}

int32_t bitcoin_wif2priv(uint8_t *addrtypep,bits256 *privkeyp,char *wifstr)
{
    int32_t len = -1; bits256 hash; uint8_t buf[64];
    if ( (len= bitcoin_base58decode(buf,wifstr)) >= 4 )
    {
        // validate with trailing hash, then remove hash
        hash = bits256_doublesha256(0,buf,len - 4);
        *addrtypep = *buf;
        memcpy(privkeyp,buf+1,32);
        if ( (buf[len - 4]&0xff) == hash.bytes[31] && (buf[len - 3]&0xff) == hash.bytes[30] &&(buf[len - 2]&0xff) == hash.bytes[29] &&(buf[len - 1]&0xff) == hash.bytes[28] )
        {
            //printf("coinaddr.(%s) valid checksum\n",coinaddr);
            return(32);
        }
    }
    return(-1);
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
    int32_t n,len = 0; char *hexstr,*spendstr = 0; cJSON *scriptjson;
    memset(vin,0,sizeof(*vin));
    vin->prev_vout = -1;
    vin->sequence = juint(vinobj,"sequence");
    if ( (hexstr= jstr(vinobj,"coinbase")) == 0 )
    {
        vin->prev_hash = jbits256(vinobj,"txid");
        vin->prev_vout = jint(vinobj,"vout");
        if ( (scriptjson= jobj(vinobj,"scriptSig")) != 0 )
            hexstr = jstr(scriptjson,"hex");
        if ( (scriptjson= jobj(vinobj,"scriptPub")) != 0 )
            spendstr = jstr(scriptjson,"hex");
    }
    if ( hexstr != 0 )
    {
        len = (int32_t)strlen(hexstr) >> 1;
        decode_hex(serialized,len,hexstr);
        vin->vinscript = serialized;
        vin->scriptlen = len;
        serialized = &serialized[len];
    } //else printf("iguana_parsevinobj: hex script missing (%s)\n",jprint(vinobj,0));
    if ( spendstr != 0 )
    {
        n = (int32_t)strlen(spendstr) >> 1;
        decode_hex(serialized,n,spendstr);
        vin->spendscript = serialized;
        vin->spendlen = n;
        len += n;
    }
    return(len);
}

cJSON *iguana_voutjson(struct iguana_info *coin,struct iguana_msgvout *vout,int32_t txi,bits256 txid)
{
    // 035f1321ed17d387e4433b2fa229c53616057964af065f98bfcae2233c5108055e OP_CHECKSIG
    char scriptstr[IGUANA_MAXSCRIPTSIZE+1],asmstr[2*IGUANA_MAXSCRIPTSIZE+1]; int32_t i,m,n,scriptlen,asmtype; struct vin_info *vp;
    uint8_t space[8192]; cJSON *addrs,*skey,*json = cJSON_CreateObject();
    vp = calloc(1,sizeof(*vp));
    jaddnum(json,"value",dstr(vout->value));
    jaddnum(json,"n",txi);
    //"scriptPubKey":{"asm":"OP_DUP OP_HASH160 5f69cb73016264270dae9f65c51f60d0e4d6fd44 OP_EQUALVERIFY OP_CHECKSIG","reqSigs":1,"type":"pubkeyhash","addresses":["RHyh1V9syARTf2pyxibz7v27D5paBeWza5"]}
    if ( vout->pk_script != 0 && vout->pk_scriptlen*2+1 < sizeof(scriptstr) )
    {
        memset(vp,0,sizeof(*vp));
        if ( (asmtype= iguana_calcrmd160(coin,asmstr,vp,vout->pk_script,vout->pk_scriptlen,txid,txi,0xffffffff)) >= 0 )
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

void iguana_addscript(struct iguana_info *coin,cJSON *dest,uint8_t *script,int32_t scriptlen,char *fieldname)
{
    char *scriptstr,scriptbuf[8192+256]; int32_t len; cJSON *scriptobj;
    if ( scriptlen < 0 )
        return;
    if ( scriptlen > sizeof(scriptbuf) )
        len = (scriptlen << 1) + 256, scriptstr = malloc(len);
    else scriptstr = scriptbuf, len = sizeof(scriptbuf);
    init_hexbytes_noT(scriptstr,script,scriptlen);
    if ( strcmp(fieldname,"coinbase") == 0 )
        jaddstr(dest,"coinbase",scriptstr);
    else
    {
        scriptobj = cJSON_CreateObject();
        jaddstr(scriptobj,"hex",scriptstr);
        iguana_expandscript(coin,scriptstr,len,script,scriptlen);
        if ( scriptstr[0] != 0 )
            jaddstr(scriptobj,"asm",scriptstr);
        if ( scriptstr != scriptbuf )
            free(scriptstr);
        jadd(dest,fieldname,scriptobj);
    }
}

cJSON *iguana_vinjson(struct iguana_info *coin,struct iguana_msgvin *vin)
{
    char str[65]; int32_t vout; cJSON *json = cJSON_CreateObject();
    vout = vin->prev_vout;
    jaddnum(json,"sequence",vin->sequence);
    if ( vout < 0 && bits256_nonz(vin->prev_hash) == 0 )
        iguana_addscript(coin,json,vin->vinscript,vin->scriptlen,"coinbase");
    else
    {
        jaddstr(json,"txid",bits256_str(str,vin->prev_hash));
        jaddnum(json,"vout",vout);
        if ( vin->scriptlen > 0 )
            iguana_addscript(coin,json,vin->vinscript,vin->scriptlen,"scriptSig");
        if ( vin->spendlen > 0 )
            iguana_addscript(coin,json,vin->spendscript,vin->spendlen,"scriptPub");
    }
    return(json);
}

int32_t iguana_vinparse(struct iguana_info *coin,int32_t rwflag,uint8_t *serialized,struct iguana_msgvin *msg)
{
    int32_t len = 0;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->scriptlen);
    if ( msg->scriptlen > IGUANA_MAXSCRIPTSIZE )
    {
        printf("iguana_vinparse illegal scriptlen.%d\n",msg->scriptlen);
        return(-1);
    }
    if ( rwflag == 0 )
    {
        msg->vinscript = &serialized[len];
        len += msg->scriptlen;
    }
    else
    {
        if ( msg->scriptlen > 0 )
        {
            memcpy(&serialized[len],msg->vinscript,msg->scriptlen);
            len += msg->scriptlen;
        }
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->sequence),&msg->sequence);
    if ( 0 )
    {
        int32_t i; char str[65];
        for (i=0; i<msg->scriptlen; i++)
            printf("%02x",msg->vinscript[i]);
        printf(" prev_hash.(%s) vout.%d [%p] scriptlen.%d rwflag.%d\n",bits256_str(str,msg->prev_hash),msg->prev_vout,msg->vinscript,msg->scriptlen,rwflag);
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
    int32_t i,n,len = 0; uint8_t *txstart = serialized; char txidstr[65]; cJSON *array=0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( json != 0 )
    {
        jaddnum(json,"version",msg->version);
        array = cJSON_CreateArray();
    }
    //printf("version.%d\n",msg->version);
    if ( coin->chain->hastimestamp != 0 )
    {
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->timestamp),&msg->timestamp);
        //char str[65]; printf("version.%d timestamp.%08x %u %s\n",msg->version,msg->timestamp,msg->timestamp,utc_str(str,msg->timestamp));
        if ( json != 0 )
            jaddnum(json,"timestamp",msg->timestamp);
    }
    //for (i=len; i<len+16; i++)
    //    printf("%02x",serialized[i]);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_in);
    //printf(" tx_in.%08x\n",msg->tx_in);
    if ( rwflag == 0 )
    {
        if ( len + sizeof(struct iguana_msgvin)*msg->tx_in > maxsize )
        {
            printf("len.%d + tx_in.%d > maxsize.%d\n",len,msg->tx_in,maxsize);
            return(-1);
        }
        maxsize -= (sizeof(struct iguana_msgvin) * msg->tx_in);
        msg->vins = (struct iguana_msgvin *)&serialized[maxsize];
        memset(msg->vins,0,sizeof(struct iguana_msgvin) * msg->tx_in);
    }
    for (i=0; i<msg->tx_in; i++)
    {
        if ( (n= iguana_vinparse(coin,rwflag,&serialized[len],&msg->vins[i])) < 0 )
            return(-1);
        //printf("vin.%d n.%d len.%d\n",i,n,len);
        len += n;
        if ( len > maxsize )
        {
            printf("invalid tx_in.%d len.%d vs maxsize.%d\n",msg->tx_in,len,maxsize);
            return(-1);
        }
        if ( array != 0 )
            jaddi(array,iguana_vinjson(coin,&msg->vins[i]));
    }
    if ( array != 0 )
    {
        jadd(json,"vin",array);
        jaddnum(json,"numvins",msg->tx_in);
        array = cJSON_CreateArray();
    }
    //for (i=len; i<len+16; i++)
    //    printf("%02x",serialized[i]);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_out);
    //printf(" txout.%d\n",msg->tx_out);
    if ( rwflag == 0 )
    {
        if ( len + sizeof(struct iguana_msgvout)*msg->tx_out > maxsize )
        {
            printf("len.%d + tx_in.%d > maxsize.%d\n",len,msg->tx_in,maxsize);
            return(-1);
        }
        maxsize -= (sizeof(struct iguana_msgvout) * msg->tx_out);
        msg->vouts = (struct iguana_msgvout *)&serialized[maxsize];
        memset(msg->vouts,0,sizeof(struct iguana_msgvout) * msg->tx_out);
    }
    for (i=0; i<msg->tx_out; i++)
    {
        if ( (n= iguana_voutparse(rwflag,&serialized[len],&msg->vouts[i])) < 0 )
            return(-1);
        len += n;
        if ( len > maxsize )
        {
            printf("invalid tx_out.%d len.%d vs maxsize.%d\n",msg->tx_out,len,maxsize);
            return(-1);
        }
        if ( array != 0 )
            jaddi(array,iguana_voutjson(coin,&msg->vouts[i],i,*txidp));
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
    if ( (msg->allocsize= iguana_rwmsgtx(coin,1,0,&serialized[len],maxsize-len,msg,&txid,vpnstr)) < 0 )
    {
        memset(txid.bytes,0,sizeof(txid));
        printf("error parsing txobj\n");
        msg->allocsize = 0;
    }
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

int32_t bitcoin_verifyvins(struct iguana_info *coin,bits256 *signedtxidp,char **signedtx,struct iguana_msgtx *msgtx,uint8_t *serialized,int32_t maxsize,struct vin_info *V,int32_t sighashsingle)
{
    bits256 txid,sigtxid,revsigtxid; uint8_t *sig,*pubkey; struct vin_info *vp;
    char txidstr[128],bigstr[2560],coinaddr[64],vpnstr[64],str[65]; uint32_t suffixlen,sigsize,pubkeysize;
    int32_t n2,i,j,k,plen,vini=0,flag,numvins,hashtype,retval,siglen,asmtype,numvouts;
    numvouts = msgtx->tx_out;
    vpnstr[0] = 0;
    *signedtx = 0;
    memset(signedtxidp,0,sizeof(*signedtxidp));
    numvins = msgtx->tx_in;
    retval = -numvins;
    for (vini=0; vini<numvins; vini++)
    {
        //saveinput = msgtx->vins[vini].vinscript;
        vp = &V[vini];
        sig = &msgtx->vins[vini].vinscript[1];
        siglen = msgtx->vins[vini].vinscript[0];
        vp->vin = msgtx->vins[vini];
        flag = 0;
        for (k=0; k<2; k++)
        {
            asmtype = (k == 0) ? IGUANA_SCRIPT_76A988AC : IGUANA_SCRIPT_76AC;
            if ( bitcoin_scriptget(coin,&hashtype,&sigsize,&pubkeysize,&suffixlen,vp,msgtx->vins[vini].vinscript,msgtx->vins[vini].scriptlen,asmtype) < 0 )
            {
                printf("cant get script for (%s).v%d\n",bits256_str(str,vp->vin.prev_hash),vp->vin.prev_vout);
                continue;
            }
            if ( sighashsingle != 0 && vini == 0 )
            {
                msgtx->tx_out = 1;
                hashtype = SIGHASH_SINGLE;
            } else msgtx->tx_out = numvouts;
            msgtx->vins[vini].spendscript = vp->spendscript;
            msgtx->vins[vini].spendlen = vp->spendlen;
            msgtx->vins[vini].sequence = vp->sequence;
            for (j=0; j<vp->N; j++)
            {
                pubkey = vp->signers[j].pubkey;
                if ( (plen= bitcoin_pubkeylen(pubkey)) < 0 )
                {
                    if ( bits256_nonz(vp->signers[j].privkey) > 0 )
                    {
                        pubkey = vp->signers[j].pubkey;
                        bitcoin_pubkey33(pubkey,vp->signers[j].privkey);
                        plen = bitcoin_pubkeylen(pubkey);
                    }
                    if ( plen < 0 )
                    {
                        printf("nopubkey for j.%d vini.%d plen.%d [%02x]\n",j,vini,plen,pubkey[0]);
                        continue;
                    }
                }
                bitcoin_address(coinaddr,coin->chain->pubtype,pubkey,plen);
                n2 = iguana_rwmsgtx(coin,1,0,serialized,maxsize,msgtx,&txid,vpnstr);
                if ( n2 > 0 )
                {
                    n2 += iguana_rwnum(1,&serialized[n2],sizeof(hashtype),&hashtype);
                    //printf("hashtype.%d [%02x]\n",hashtype,sig[siglen-1]);
                    revsigtxid = bits256_doublesha256(txidstr,serialized,n2);
                    for (i=0; i<sizeof(revsigtxid); i++)
                        sigtxid.bytes[31-i] = revsigtxid.bytes[i];
                    if ( 1 && bits256_nonz(vp->signers[j].privkey) != 0 )
                    {
                        siglen = bitcoin_sign(vp->signers[j].sig,sizeof(vp->signers[j].sig),sigtxid.bytes,sizeof(sigtxid),vp->signers[j].privkey);
                        sig = vp->signers[j].sig;
                        sig[siglen++] = hashtype;
                        vp->signers[j].siglen = siglen;
                        msgtx->vins[vini].vinscript = calloc(1,siglen*2+256); // fix this memleak!
                        msgtx->vins[vini].scriptlen = bitcoin_scriptsig(coin,msgtx->vins[vini].vinscript,0,(const struct vin_info *)vp,msgtx);
                        //for (i=0; i<siglen; i++)
                        //    printf("%02x",sig[i]);
                        //printf(" SIGNEDTX.[%02x] plen.%d siglen.%d\n",sig[siglen-1],plen,siglen);
                    }
                    if ( bitcoin_verify(sig,siglen,sigtxid.bytes,sizeof(sigtxid),vp->signers[j].pubkey,bitcoin_pubkeylen(vp->signers[j].pubkey)) < 0 )
                    {
                        init_hexbytes_noT(bigstr,serialized,n2);
                        printf("(%s) doesnt verify hash2.%s\n",bigstr,bits256_str(str,sigtxid));
                        *signedtx = iguana_rawtxbytes(coin,0,msgtx);
                        *signedtxidp = msgtx->txid;
                        printf("SIG.%d ERROR %s\n",vini,*signedtx);
                    }
                    else
                    {
                        cJSON *txobj = cJSON_CreateObject();
                        *signedtx = iguana_rawtxbytes(coin,txobj,msgtx);
                        *signedtxidp = msgtx->txid;
                        //printf("SIG.%d VERIFIED %s (%s)\n",vini,*signedtx,jprint(txobj,1));
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

int32_t bitcoin_verifytx(struct iguana_info *coin,bits256 *signedtxidp,char **signedtx,char *rawtxstr,struct vin_info *V)
{
    int32_t len,maxsize,numvins,retval = -1; uint8_t *serialized,*serialized2;
    struct iguana_msgtx msgtx; bits256 txid; char vpnstr[64];
    len = (int32_t)strlen(rawtxstr);
    maxsize = len + 32768;
    serialized = calloc(1,maxsize), serialized2 = calloc(1,maxsize);
    len >>= 1;
    vpnstr[0] = 0;
    decode_hex(serialized,len,rawtxstr);
    memset(&msgtx,0,sizeof(msgtx));
    if ( iguana_rwmsgtx(coin,0,0,serialized,maxsize,&msgtx,&txid,vpnstr) > 0 )
    {
        numvins = msgtx.tx_in;
        if ( bitcoin_verifyvins(coin,signedtxidp,signedtx,&msgtx,serialized2,maxsize,V,0) == 0 )
            retval = 0;
        else printf("bitcoin_verifytx: bitcoin_verifyvins error\n");
    } else printf("bitcoin_verifytx: error iguana_rwmsgtx\n");
    free(serialized), free(serialized2);
    return(retval);
}

char *bitcoin_json2hex(struct iguana_info *coin,bits256 *txidp,cJSON *txjson)
{
    int32_t txstart; uint8_t *serialized; struct iguana_msgtx msgtx; char *txbytes = 0;
    serialized = malloc(IGUANA_MAXPACKETSIZE*1.5);
    *txidp = iguana_parsetxobj(coin,&txstart,serialized,IGUANA_MAXPACKETSIZE*1.5,&msgtx,txjson);
    if ( msgtx.allocsize > 0 )
    {
        txbytes = malloc(msgtx.allocsize*2 + 1);
        init_hexbytes_noT(txbytes,&serialized[txstart],msgtx.allocsize);
    } else printf("bitcoin_txtest: zero msgtx allocsize.(%s)\n",jprint(txjson,0));
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
    serialized = malloc(len + 32768);
    decode_hex(serialized,len,txbytes);
    vpnstr[0] = 0;
    memset(txidp,0,sizeof(*txidp));
    printf("B bitcoin_hex2json len.%d\n",len);
    if ( (n= iguana_rwmsgtx(coin,0,txobj,serialized,len + 32768,msgtx,txidp,vpnstr)) <= 0 )
    {
        printf("error from rwmsgtx\n");
        free_json(txobj);
        txobj = 0;
    }
    free(serialized);
    return(txobj);
}

cJSON *bitcoin_createtx(struct iguana_info *coin,uint32_t locktime)
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
    jdelete(txobj,"vout");
    item = cJSON_CreateObject();
    jaddnum(item,"value",dstr(satoshis));
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

cJSON *bitcoin_addinput(struct iguana_info *coin,cJSON *txobj,bits256 txid,int32_t vout,uint32_t sequenceid,uint8_t *script,int32_t scriptlen,uint8_t *redeemscript,int32_t p2shlen)
{
    cJSON *item,*vins; char p2shscriptstr[IGUANA_MAXSCRIPTSIZE*2+1];
    vins = jduplicate(jobj(txobj,"vin"));
    jdelete(txobj,"vin");
    item = cJSON_CreateObject();
    if ( script != 0 && scriptlen > 0 )
        iguana_addscript(coin,item,script,scriptlen,"scriptPubKey");
    if ( redeemscript != 0 && p2shlen > 0 )
    {
        init_hexbytes_noT(p2shscriptstr,redeemscript,p2shlen);
        jaddstr(item,"redeemScript",p2shscriptstr);
    }
    jaddbits256(item,"txid",txid);
    jaddnum(item,"vout",vout);
    jaddnum(item,"sequence",sequenceid);
    jaddi(vins,item);
    jadd(txobj,"vin",vins);
    printf("addvin -> (%s)\n",jprint(txobj,0));
    return(txobj);
}

struct bitcoin_unspent *iguana_bestfit(struct iguana_info *coin,struct bitcoin_unspent *unspents,int32_t numunspents,uint64_t value,int32_t mode)
{
    int32_t i; uint64_t above,below,gap,atx_value; struct bitcoin_unspent *vin,*abovevin,*belowvin;
    abovevin = belowvin = 0;
    for (above=below=i=0; i<numunspents; i++)
    {
        vin = &unspents[i];
        atx_value = vin->value;
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

struct bitcoin_spend *iguana_spendset(struct supernet_info *myinfo,struct iguana_info *coin,int64_t amount,int64_t txfee,char *account)
{
    int32_t i,mode,numunspents,maxinputs = 1024; struct bitcoin_unspent *ptr,*up;
    struct bitcoin_unspent *ups; struct bitcoin_spend *spend; double balance; int64_t remains,smallest = 0;
    if ( (ups= iguana_unspentsget(myinfo,coin,0,&balance,&numunspents,coin->chain->minconfirms,account)) == 0 )
        return(0);
    spend = calloc(1,sizeof(*spend) + sizeof(*spend->inputs) * maxinputs);
    spend->txfee = txfee;
    remains = txfee + amount;
    spend->satoshis = remains;
    ptr = spend->inputs;
    for (i=0; i<maxinputs; i++,ptr++)
    {
        for (mode=1; mode>=0; mode--)
            if ( (up= iguana_bestfit(coin,ups,numunspents,remains,mode)) != 0 )
                break;
        if ( up != 0 )
        {
            if ( smallest == 0 || up->value < smallest )
            {
                smallest = up->value;
                memcpy(spend->change160,up->rmd160,sizeof(spend->change160));
            }
            spend->input_satoshis += up->value;
            spend->inputs[spend->numinputs++] = *up;
            if ( spend->input_satoshis >= spend->satoshis )
            {
                // numinputs 1 -> (1.00074485 - spend 0.41030880) = net 0.59043605 vs amount 0.40030880 change 0.40030880 -> txfee 0.01000000 vs chainfee 0.01000000
                spend->change = (spend->input_satoshis - spend->satoshis) - txfee;
                printf("numinputs %d -> (%.8f - spend %.8f) = change %.8f -> txfee %.8f vs chainfee %.8f\n",spend->numinputs,dstr(spend->input_satoshis),dstr(spend->satoshis),dstr(spend->change),dstr(spend->input_satoshis - spend->change - spend->satoshis),dstr(txfee));
                break;
            }
            remains -= up->value;
        } else break;
    }
    if ( spend->input_satoshis >= spend->satoshis )
    {
        spend = realloc(spend,sizeof(*spend) + sizeof(*spend->inputs) * spend->numinputs);
        return(spend);
    }
    else
    {
        free(spend);
        return(0);
    }
}

void iguana_addinputs(struct iguana_info *coin,struct bitcoin_spend *spend,cJSON *txobj,uint32_t sequence)
{
    int32_t i;
    for (i=0; i<spend->numinputs; i++)
    {
        spend->inputs[i].sequence = sequence;
        bitcoin_addinput(coin,txobj,spend->inputs[i].txid,spend->inputs[i].vout,spend->inputs[i].sequence,spend->inputs[i].spendscript,spend->inputs[i].spendlen,spend->inputs[i].p2shscript,spend->inputs[i].p2shlen);
    }
}

cJSON *iguana_signtx(struct iguana_info *coin,bits256 *txidp,char **signedtxp,struct bitcoin_spend *spend,cJSON *txobj)
{
    int32_t i,j; char *rawtxstr; struct vin_info V; bits256 txid;
    for (i=0; i<spend->numinputs; i++) // N times less efficient, but for small number of inputs ok
    {
        if ( *signedtxp != 0 )
        {
            if ( txobj != 0 )
                free_json(txobj);
            txobj = bitcoin_hex2json(coin,&txid,0,*signedtxp);
            free(*signedtxp);
        }
        if ( (rawtxstr= bitcoin_json2hex(coin,&txid,txobj)) != 0 )
        {
            memset(&V,0,sizeof(V));
            for (j=0; j<sizeof(spend->inputs[i].privkeys)/sizeof(*spend->inputs[i].privkeys); j++)
            {
                if ( bits256_nonz(spend->inputs[i].privkeys[j]) != 0 )
                    V.signers[j].privkey = spend->inputs[i].privkeys[j];
            }
            if ( spend->inputs[i].spendlen > 0 )
            {
                memcpy(V.spendscript,spend->inputs[i].spendscript,spend->inputs[i].spendlen);
                V.spendlen = spend->inputs[i].spendlen;
            }
            V.sequence = spend->inputs[i].sequence;
            //printf("json2hex.(%s)\n",rawtxstr);
            bitcoin_verifytx(coin,txidp,signedtxp,rawtxstr,&V);
            //printf("json2hex.(%s)\n",rawtxstr);
            free(rawtxstr);
        } else break;
    }
    if ( *signedtxp != 0 && i != spend->numinputs )
        free(*signedtxp), *signedtxp = 0;
    return(txobj);
}

int32_t iguana_validatesigs(struct iguana_info *coin,struct iguana_msgvin *vin)
{
    // multiple coins
    // ro -> vouts collision, purgeable
    // 
    return(0);
}

#ifdef testing
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
#endif

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

cJSON *bitcoin_txtest(struct iguana_info *coin,char *rawtxstr,bits256 txid)
{
    struct iguana_msgtx msgtx; char str[65],str2[65]; bits256 checktxid,blockhash,signedtxid;
    cJSON *retjson,*txjson; uint8_t *serialized,*serialized2; uint32_t firstvout; 
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
        if ( (firstvout= iguana_unspentindfind(coin,&height,txid,0,coin->bundlescount-1)) != 0 )
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

uint64_t bitcoin_parseunspent(struct iguana_info *coin,struct bitcoin_unspent *unspent,double minconfirms,char *account,cJSON *item)
{
    uint8_t addrtype; char *hexstr,*wifstr,coinaddr[64],args[128];
    memset(unspent,0,sizeof(*unspent));
    if ( jstr(item,"address") != 0 )
    {
        safecopy(coinaddr,jstr(item,"address"),sizeof(coinaddr));
        bitcoin_addr2rmd160(&unspent->addrtype,unspent->rmd160,coinaddr);
        sprintf(args,"[\"%s\"]",coinaddr);
        wifstr = bitcoind_RPC(0,coin->symbol,coin->chain->serverport,coin->chain->userpass,"dumpprivkey",args);
        if ( wifstr != 0 )
        {
            bitcoin_wif2priv(&addrtype,&unspent->privkeys[0],wifstr);
            //printf("wifstr.(%s) -> %s\n",wifstr,bits256_str(str,unspent->privkeys[0]));
            free(wifstr);
        } else fprintf(stderr,"error (%s) cant find privkey\n",coinaddr);
    }
    if ( (account == 0 || jstr(item,"account") == 0 || strcmp(account,jstr(item,"account")) == 0) && (minconfirms <= 0 || juint(item,"confirmations") >= minconfirms-SMALLVAL) )
    {
        if ( (hexstr= jstr(item,"scriptPubKey")) != 0 )
        {
            unspent->spendlen = (int32_t)strlen(hexstr) >> 1;
            if ( unspent->spendlen < sizeof(unspent->spendscript) )
                decode_hex(unspent->spendscript,unspent->spendlen,hexstr);
        }
        unspent->txid = jbits256(item,"txid");
        unspent->value = SATOSHIDEN * jdouble(item,"amount");
        unspent->vout = jint(item,"vout");
        //char str[65]; printf("(%s) -> %s %.8f scriptlen.%d\n",jprint(item,0),bits256_str(str,unspent->txid),dstr(unspent->value),unspent->scriptlen);
    } else printf("skip.(%s) minconfirms.%f\n",jprint(item,0),minconfirms);
    return(unspent->value);
}

struct bitcoin_unspent *iguana_unspentsget(struct supernet_info *myinfo,struct iguana_info *coin,char **retstrp,double *balancep,int32_t *numunspentsp,double minconfirms,char *account)
{
    char params[128],*retstr; uint64_t value,total = 0; struct bitcoin_unspent *unspents=0; cJSON *utxo; int32_t i,n;
    if ( account != 0 && account[0] == 0 )
        account = 0;
    *numunspentsp = 0;
    if ( retstrp != 0 )
        *retstrp = 0;
    sprintf(params,"%.0f, 99999999",minconfirms);
    if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"listunspent",params)) != 0 )
    {
        //printf("sss unspents.(%s)\n",retstr);
        if ( (utxo= cJSON_Parse(retstr)) != 0 )
        {
            n = 0;
            if ( (*numunspentsp= cJSON_GetArraySize(utxo)) > 0 )
            {
                unspents = calloc(*numunspentsp,sizeof(*unspents));
                for (i=0; i<*numunspentsp; i++)
                {
                    value = bitcoin_parseunspent(coin,&unspents[n],minconfirms,account,jitem(utxo,i));
                    //printf("i.%d n.%d value %.8f\n",i,n,dstr(value));
                    if ( value != 0 )
                    {
                        total += value;
                        n++;
                    }
                }
            }
            //printf("numunspents.%d -> %d total %.8f\n",*numunspentsp,n,dstr(total));
            *numunspentsp = n;
            free_json(utxo);
        } else printf("error parsing.(%s)\n",retstr);
        if ( retstrp != 0 )
            *retstrp = retstr;
        else free(retstr);
    }
    *balancep = dstr(total);
    return(unspents);
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
    instantdex_offerfind(SuperNET_MYINFO(0),exchange,bids,asks,0,base,rel,1);
    //printf("bids.(%s) asks.(%s)\n",jprint(bids,0),jprint(asks,0));
    retjson = cJSON_CreateObject();
    cJSON_AddItemToObject(retjson,"bids",bids);
    cJSON_AddItemToObject(retjson,"asks",asks);
    hbla = exchanges777_json_orderbook(exchange,commission,base,rel,bidasks,maxdepth,retjson,0,"bids","asks",0,0,invert);
    free_json(retjson);
    return(hbla);
}

char *PARSEBALANCE(struct exchange_info *exchange,double *balancep,char *coinstr,cJSON *argjson)
{
    cJSON *item;
    *balancep = 0;
    if ( (item= jobj(argjson,coinstr)) != 0 )
    {
        *balancep = jdouble(item,"balance");
        return(jprint(item,0));
    }
    return(clonestr("{\"error\":\"no item for specified coin\"}"));
}

cJSON *BALANCES(struct exchange_info *exchange,cJSON *argjson)
{
    double balance; char *retstr; int32_t i,numunspents,minconfirms; struct iguana_info *coin;
    struct supernet_info *myinfo; struct bitcoin_unspent *unspents; cJSON *item,*retjson,*utxo;
    retjson = cJSON_CreateArray();
    myinfo = SuperNET_accountfind(argjson);
    for (i=0; i<IGUANA_MAXCOINS; i++)
    {
        if ( (coin= Coins[i]) != 0 && coin->chain->serverport[0] != 0 )
        {
            balance = 0.;
            minconfirms = juint(argjson,"minconfirms");
            if ( minconfirms < coin->minconfirms )
                minconfirms = coin->minconfirms;
            if ( (unspents= iguana_unspentsget(myinfo,coin,&retstr,&balance,&numunspents,minconfirms,0)) != 0 )
            {
                item = cJSON_CreateObject();
                jaddnum(retjson,"balance",balance);
                if ( retstr != 0 )
                {
                    if ( (utxo= cJSON_Parse(retstr)) != 0 )
                    {
                        jadd(item,"unspents",utxo);
                        jaddnum(item,"numunspents",numunspents);
                    }
                    free(retstr);
                }
                free(unspents);
                jadd(retjson,coin->symbol,item);
            }
        }
    }
    return(retjson);
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
    char *str,*retstr,coinaddr[64]; uint64_t txid = 0; cJSON *json=0;
    struct instantdex_accept *ap;
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
            jaddnum(json,"minperc",jdouble(argjson,"minperc"));
            //printf("trade dir.%d (%s/%s) %.6f vol %.8f\n",dir,base,"BTC",price,volume);
            if ( (str= instantdex_createaccept(myinfo,&ap,exchange,base,"BTC",price,volume,-dir,dir > 0 ? "BTC" : base,INSTANTDEX_OFFERDURATION,myinfo->myaddr.nxt64bits,0,jdouble(argjson,"minperc"))) != 0 && ap != 0 )
                retstr = instantdex_checkoffer(myinfo,&txid,exchange,ap,json), free(str);
            else printf("null return queueaccept\n");
            if ( retstrp != 0 )
                *retstrp = retstr;
        }
    }
    return(txid);
}

char *ORDERSTATUS(struct exchange_info *exchange,uint64_t orderid,cJSON *argjson)
{
    struct instantdex_accept *ap; struct bitcoin_swapinfo *swap; cJSON *retjson;
    retjson = cJSON_CreateObject();
    struct supernet_info *myinfo = SuperNET_accountfind(argjson);
    if ( (swap= instantdex_statemachinefind(myinfo,exchange,orderid,1)) != 0 )
        jadd(retjson,"result",instantdex_statemachinejson(swap));
    else if ( (ap= instantdex_offerfind(myinfo,exchange,0,0,orderid,"*","*",1)) != 0 )
        jadd(retjson,"result",instantdex_acceptjson(ap));
    else if ( (swap= instantdex_historyfind(myinfo,exchange,orderid)) != 0 )
        jadd(retjson,"result",instantdex_historyjson(swap));
    else jaddstr(retjson,"error","couldnt find orderid");
    return(jprint(retjson,1));
}

char *CANCELORDER(struct exchange_info *exchange,uint64_t orderid,cJSON *argjson)
{
    struct instantdex_accept *ap = 0; cJSON *retjson; struct bitcoin_swapinfo *swap=0;
    struct supernet_info *myinfo = SuperNET_accountfind(argjson);
    retjson = cJSON_CreateObject();
    if ( (ap= instantdex_offerfind(myinfo,exchange,0,0,orderid,"*","*",1)) != 0 )
    {
        ap->dead = (uint32_t)time(NULL);
        jadd(retjson,"orderid",instantdex_acceptjson(ap));
        jaddstr(retjson,"result","killed orderid, but might have pending");
    }
    else if ( (swap= instantdex_statemachinefind(myinfo,exchange,orderid,1)) != 0 )
    {
        jadd(retjson,"orderid",instantdex_statemachinejson(swap));
        jaddstr(retjson,"result","killed statemachine orderid, but might have pending");
    }
    return(jprint(retjson,1));
}

char *OPENORDERS(struct exchange_info *exchange,cJSON *argjson)
{
    cJSON *retjson,*bids,*asks; struct supernet_info *myinfo = SuperNET_accountfind(argjson);
    bids = cJSON_CreateArray();
    asks = cJSON_CreateArray();
    instantdex_offerfind(myinfo,exchange,bids,asks,0,"*","*",1);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jadd(retjson,"bids",bids);
    jadd(retjson,"asks",asks);
    return(jprint(retjson,1));
}

char *TRADEHISTORY(struct exchange_info *exchange,cJSON *argjson)
{
    struct bitcoin_swapinfo PAD,*swap; cJSON *retjson = cJSON_CreateArray();
    memset(&PAD,0,sizeof(PAD));
    queue_enqueue("historyQ",&exchange->historyQ,&PAD.DL,0);
    while ( (swap= queue_dequeue(&exchange->historyQ,0)) != 0 && swap != &PAD )
    {
        jaddi(retjson,instantdex_historyjson(swap));
        queue_enqueue("historyQ",&exchange->historyQ,&swap->DL,0);
    }
    return(jprint(retjson,1));
}

char *WITHDRAW(struct exchange_info *exchange,char *base,double amount,char *destaddr,cJSON *argjson)
{
    //struct supernet_info *myinfo = SuperNET_accountfind(argjson);
    // invoke conversion or transfer!
    return(clonestr("{\"error\":\"what does it mean to withdraw bitcoins that are in your wallet\"}"));
}

struct exchange_funcs bitcoin_funcs = EXCHANGE_FUNCS(bitcoin,EXCHANGE_NAME);

#include "exchange_undefs.h"


#include "../../includes/iguana_apidefs.h"
#include "../../includes/iguana_apideclares.h"

char *_setVsigner(struct iguana_info *coin,struct vin_info *V,int32_t ind,char *pubstr,char *wifstr)
{
    uint8_t addrtype;
    decode_hex(V->signers[ind].pubkey,(int32_t)strlen(pubstr)/2,pubstr);
    bitcoin_wif2priv(&addrtype,&V->signers[ind].privkey,wifstr);
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
    struct vin_info V; uint8_t p2sh_rmd160[20],serialized[2096],spendscript[32]; int32_t spendlen;
    char msigaddr[64],*retstr; cJSON *retjson,*txobj; struct iguana_info *active;
    bits256 signedtxid; char *signedtx;
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
    if ( pubA[0] != 0 && (retstr= _setVsigner(active,&V,0,pubA,wifA)) != 0 )
        return(retstr);
    if ( N >= 2 && pubB[0] != 0 && (retstr= _setVsigner(active,&V,1,pubB,wifC)) != 0 )
        return(retstr);
    if ( N == 3 && pubC[0] != 0 && (retstr= _setVsigner(active,&V,2,pubC,wifC)) != 0 )
        return(retstr);
    V.M = M, V.N = N, V.type = IGUANA_SCRIPT_P2SH;
    V.p2shlen = bitcoin_MofNspendscript(p2sh_rmd160,V.p2shscript,0,&V);
    spendlen = bitcoin_p2shspend(spendscript,0,p2sh_rmd160);
    bitcoin_addinput(active,txobj,vintxid,vinvout,0xffffffff,spendscript,spendlen,V.p2shscript,V.p2shlen);
    bitcoin_address(msigaddr,active->chain->p2shtype,V.p2shscript,V.p2shlen);
    retjson = cJSON_CreateObject();
    if ( bitcoin_verifyvins(active,&signedtxid,&signedtx,&msgtx,serialized,sizeof(serialized),&V,0) == 0 )
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

