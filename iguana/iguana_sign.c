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


int32_t iguana_vinparse(struct iguana_info *coin,int32_t rwflag,uint8_t *serialized,struct iguana_msgvin *msg)
{
    //int32_t sighash,i,plen,len = 0; struct vin_info V; uint32_t sigsize,pubkeysize,p2shsize,suffixlen;
    int32_t p2shlen,len = 0; uint32_t tmp;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    if ( rwflag == 1 )
        tmp = msg->scriptlen;
    len += iguana_rwvarint32(rwflag,&serialized[len],&tmp);
    if ( rwflag == 0 )
        msg->scriptlen = tmp;
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
    else if ( msg->vinscript != 0 && msg->scriptlen > 0 )
    {
        memcpy(&serialized[len],msg->vinscript,msg->scriptlen), len += msg->scriptlen; // pubkeys here
        if ( (p2shlen= msg->p2shlen) > 0 && msg->redeemscript != 0 )
        {
            if ( p2shlen > msg->suffixlen )
            {
                p2shlen -= msg->suffixlen;
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
            }
            if ( msg->suffixlen > 0 )
                memcpy(&serialized[len],&msg->redeemscript[msg->scriptlen - msg->suffixlen],msg->suffixlen), len += msg->suffixlen;
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

cJSON *iguana_scriptpubkeys(struct iguana_info *coin,uint8_t *script,int32_t scriptlen,bits256 txid,int16_t vout,uint32_t sequenceid)
{
    int32_t type,i,n,plen; struct vin_info V; cJSON *pubkeys; char pubkeystr[256];
    pubkeys = cJSON_CreateArray();
    if ( (type= iguana_calcrmd160(coin,0,&V,script,scriptlen,txid,vout,sequenceid)) >= 0 )
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
            iguana_addscript(coin,json,vin->spendscript,vin->spendlen,"scriptPubKey");
        if ( vin->p2shlen > 0 )
            iguana_addscript(coin,json,vin->redeemscript,vin->p2shlen,"redeemScript");
    }
    return(json);
}

int32_t iguana_parsevinobj(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_msgvin *vin,cJSON *vinobj,struct vin_info *V)
{
    struct iguana_waddress *waddr; struct iguana_waccount *wacct; int32_t i,n,plen,len = 0; char *suffixstr,*pubkeystr,*hexstr = 0,*redeemstr = 0,*spendstr = 0; cJSON *scriptjson = 0,*obj,*pubkeysjson = 0;
    //printf("PARSEVIN.(%s)\n",jprint(vinobj,0));
    if ( V == 0 )
        memset(vin,0,sizeof(*vin));
    vin->prev_vout = -1;
    if ( jobj(vinobj,"sequence") != 0 )
        vin->sequence = juint(vinobj,"sequence");
    else vin->sequence = 0xffffffff;
    if ( (hexstr= jstr(vinobj,"coinbase")) == 0 )
    {
        vin->prev_hash = jbits256(vinobj,"txid");
        vin->prev_vout = jint(vinobj,"vout");
        if ( (scriptjson= jobj(vinobj,"scriptSig")) != 0 )
            hexstr = jstr(scriptjson,"hex");
        if ( ((spendstr= jstr(vinobj,"scriptPub")) == 0 && (spendstr= jstr(vinobj,"scriptPubkey")) == 0) || is_hexstr(spendstr,(int32_t)strlen(spendstr)) <= 0 )
        {
            if ( (obj= jobj(vinobj,"scriptPub")) != 0 || (obj= jobj(vinobj,"scriptPubkey")) != 0 )
                spendstr = jstr(obj,"hex");
        }
        if ( (redeemstr= jstr(vinobj,"redeemScript")) == 0 || is_hexstr(redeemstr,(int32_t)strlen(redeemstr)) <= 0 )
        {
            if ( (obj= jobj(vinobj,"redeemScript")) != 0 )
                redeemstr = jstr(obj,"hex");
        }
    }
    if ( hexstr != 0 )
    {
        n = (int32_t)strlen(hexstr) >> 1;
        decode_hex(serialized,n,hexstr);
        vin->vinscript = serialized;
        vin->scriptlen = n;
    } //else printf("iguana_parsevinobj: hex script missing (%s)\n",jprint(vinobj,0));
    if ( V != 0 )
    {
        if ( vin->vinscript == 0 )
        {
            if ( (V->unspentind= iguana_unspentindfind(coin,V->coinaddr,V->spendscript,&V->spendlen,&V->amount,&V->height,vin->prev_hash,vin->prev_vout,coin->bundlescount-1)) > 0 )
            {
                if ( V->coinaddr[0] != 0 && (waddr= iguana_waddresssearch(myinfo,coin,&wacct,V->coinaddr)) != 0 )
                {
                    memcpy(V->signers[0].pubkey,waddr->pubkey,bitcoin_pubkeylen(waddr->pubkey));
                }
                printf("V %.8f (%s) spendscript.[%d]\n",dstr(V->amount),V->coinaddr,V->spendlen);
            }
        }
        if ( (pubkeysjson= jarray(&n,vinobj,"pubkeys")) != 0 )
        {
            if ( vin->vinscript == 0 )
            {
                vin->vinscript = serialized;
                vin->vinscript[0] = 0;
                vin->scriptlen = 1;
            }
            for (i=0; i<n; i++)
            {
                if ( (pubkeystr= jstr(jitem(pubkeysjson,i),0)) != 0 && (plen= (int32_t)strlen(pubkeystr) >> 1) > 0 )
                {
                    vin->vinscript[vin->scriptlen++] = plen;
                    decode_hex(&vin->vinscript[vin->scriptlen],plen,pubkeystr);
                    memcpy(V->signers[i].pubkey,&vin->vinscript[vin->scriptlen],plen);
                    vin->scriptlen += plen;
                }
            }
        }
        if ( vin->vinscript != 0 )
            serialized = &vin->vinscript[vin->scriptlen];
        len = vin->scriptlen;
        if ( redeemstr != 0 )
        {
            n = (int32_t)strlen(redeemstr) >> 1;
            decode_hex(serialized,n,redeemstr);
            vin->redeemscript = serialized;
            V->p2shlen = vin->p2shlen = n;
            memcpy(V->p2shscript,serialized,n);
        }
        if ( (suffixstr= jstr(vinobj,"suffix")) != 0 && is_hexstr(suffixstr,(int32_t)strlen(suffixstr)) > 0 )
        {
            if ( vin->redeemscript == 0 )
            {
                vin->redeemscript = serialized;
                vin->redeemscript[0] = 0;
            }
            n = (int32_t)strlen(suffixstr) >> 1;
            decode_hex(&vin->redeemscript[vin->p2shlen],n,suffixstr);
            vin->p2shlen += n;
        }
        len += vin->p2shlen;
        serialized = vin->redeemscript != 0 ? &vin->redeemscript[vin->p2shlen] : &serialized[len];
        if ( spendstr != 0 )
        {
            n = (int32_t)strlen(spendstr) >> 1;
            decode_hex(serialized,n,spendstr);
            vin->spendscript = serialized;
            vin->spendlen = n;
        }
        len += vin->spendlen;
    }
    return(len);
}

int32_t iguana_parsevoutobj(struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_msgvout *vout,cJSON *voutobj)
{
    int32_t len = 0; cJSON *skey; char *hexstr;
    memset(vout,0,sizeof(*vout));
    if ( jobj(voutobj,"satoshis") != 0 )
        vout->value = j64bits(voutobj,"satoshis");
    else vout->value = jdouble(voutobj,"value") * SATOSHIDEN;
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

cJSON *iguana_voutjson(struct iguana_info *coin,struct iguana_msgvout *vout,int32_t txi,bits256 txid)
{
    // 035f1321ed17d387e4433b2fa229c53616057964af065f98bfcae2233c5108055e OP_CHECKSIG
    char scriptstr[IGUANA_MAXSCRIPTSIZE+1],asmstr[2*IGUANA_MAXSCRIPTSIZE+1]; int32_t i,m,n,scriptlen,asmtype; struct vin_info *vp;
    uint8_t space[8192]; cJSON *addrs,*skey,*json = cJSON_CreateObject();
    vp = calloc(1,sizeof(*vp));
    jadd64bits(json,"satoshis",vout->value);
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

bits256 iguana_parsetxobj(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *txstartp,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,cJSON *txobj,struct vin_info *V) // json -> serialized + (msg,V)
{
    int32_t i,numvins,numvouts,len = 0; cJSON *array=0; bits256 txid; char vpnstr[64];
    memset(&txid,0,sizeof(txid));
    if ( txobj == 0 )
        return(txid);
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
                len += iguana_parsevinobj(myinfo,coin,&serialized[len],maxsize,&msg->vins[i],jitem(array,i),V!=0?&V[i]:0);
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

cJSON *bitcoin_addinput(struct iguana_info *coin,cJSON *txobj,bits256 txid,int32_t vout,uint32_t sequenceid,uint8_t *spendscript,int32_t spendlen,uint8_t *redeemscript,int32_t p2shlen,uint8_t *pubkeys[],int32_t numpubkeys)
{
    cJSON *item,*vins; char p2shscriptstr[IGUANA_MAXSCRIPTSIZE*2+1]; uint8_t *script,len;
    vins = jduplicate(jobj(txobj,"vin"));
    jdelete(txobj,"vin");
    item = cJSON_CreateObject();
    if ( spendscript != 0 && spendscript > 0 )
    {
        iguana_addscript(coin,item,spendscript,spendlen,"scriptPubKey");
        script = spendscript, len = spendlen;
    }
    else if ( redeemscript != 0 && p2shlen > 0 )
    {
        init_hexbytes_noT(p2shscriptstr,redeemscript,p2shlen);
        jaddstr(item,"redeemScript",p2shscriptstr);
        script = redeemscript, len = p2shlen;
    } else script = 0;
    if ( script != 0 && numpubkeys == 0 )
        jadd(item,"pubkeys",iguana_scriptpubkeys(coin,script,len,txid,vout,sequenceid));
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

char *bitcoin_json2hex(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,cJSON *txjson,struct vin_info *V)
{
    int32_t txstart; uint8_t *serialized; struct iguana_msgtx msgtx; char *txbytes = 0;
    if ( txjson == 0 )
    {
        memset(txidp,0,sizeof(*txidp));
        return(0);
    }
    serialized = malloc(IGUANA_MAXPACKETSIZE*1.5);
    *txidp = iguana_parsetxobj(myinfo,coin,&txstart,serialized,IGUANA_MAXPACKETSIZE*1.5,&msgtx,txjson,V);
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
    if ( (n= iguana_rwmsgtx(coin,0,txobj,serialized,len + 32768,msgtx,txidp,vpnstr)) <= 0 )
    {
        printf("error from rwmsgtx\n");
        free_json(txobj);
        txobj = 0;
    }
    free(serialized);
    return(txobj);
}

bits256 bitcoin_sigtxid(struct iguana_info *coin,uint8_t *serialized,int32_t maxlen,struct iguana_msgtx *msgtx,int32_t vini,uint8_t *spendscript,int32_t spendlen,int32_t hashtype,char *vpnstr)
{
    int32_t i,len; bits256 sigtxid,txid,revsigtxid; struct iguana_msgtx dest;
    dest = *msgtx;
    memset(sigtxid.bytes,0,sizeof(sigtxid));
    if ( hashtype != SIGHASH_ALL )
    {
        printf("currently only SIGHASH_ALL supported, not %d\n",hashtype);
        return(sigtxid);
    }
    for (i=0; i<msgtx->tx_in; i++)
    {
        if ( i == vini )
        {
            dest.vins[i].vinscript = spendscript;
            dest.vins[i].scriptlen = spendlen;
        }
        else
        {
            dest.vins[i].vinscript = (uint8_t *)"";
            dest.vins[i].scriptlen = 0;
        }
        dest.vins[i].p2shlen = 0;
        dest.vins[i].redeemscript = 0;
    }
    len = iguana_rwmsgtx(coin,1,0,serialized,maxlen,&dest,&txid,vpnstr);
    if ( len > 0 )
    {
        len += iguana_rwnum(1,&serialized[len],sizeof(hashtype),&hashtype);
        revsigtxid = bits256_doublesha256(0,serialized,len);
        for (i=0; i<sizeof(revsigtxid); i++)
            sigtxid.bytes[31-i] = revsigtxid.bytes[i];
    }
    return(sigtxid);
}

int32_t iguana_msgtx_Vset(struct iguana_info *coin,uint8_t *serialized,int32_t maxlen,struct iguana_msgtx *msgtx,struct vin_info *V)
{
    int32_t vini,j,scriptlen,p2shlen,siglen,plen,len = 0; uint8_t *script; struct vin_info *vp;
    for (vini=0; vini<msgtx->tx_in; vini++)
    {
        vp = &V[vini];
        msgtx->vins[vini].vinscript = script = &serialized[len];
        msgtx->vins[vini].vinscript[0] = 0;
        scriptlen = 0;
        for (j=0; j<vp->N; j++)
        {
            if ( (siglen= vp->signers[j].siglen) > 0 )
            {
                script[scriptlen++] = siglen;
                memcpy(&script[scriptlen],vp->signers[j].sig,siglen);
                scriptlen += siglen;
            }
        }
        for (j=0; j<vp->N; j++)
        {
            if ( (plen= bitcoin_pubkeylen(vp->signers[j].pubkey)) > 0 )
            {
                script[scriptlen++] = plen;
                memcpy(&script[scriptlen],vp->signers[j].pubkey,plen);
                scriptlen += plen;
            }
        }
        msgtx->vins[vini].scriptlen = scriptlen;
        if ( (p2shlen= vp->p2shlen) > 0 )
        {
            msgtx->vins[vini].redeemscript = &script[scriptlen];
            if ( p2shlen < 76 )
                script[scriptlen++] = p2shlen;
            else if ( p2shlen <= 0xff )
            {
                script[scriptlen++] = 0x4c;
                script[scriptlen++] = p2shlen;
            }
            else if ( p2shlen <= 0xffff )
            {
                script[scriptlen++] = 0x4d;
                script[scriptlen++] = (p2shlen & 0xff);
                script[scriptlen++] = ((p2shlen >> 8) & 0xff);
            } else return(-1);
            memcpy(&script[scriptlen],vp->p2shscript,p2shlen), scriptlen += p2shlen;
            if ( (msgtx->vins[vini].suffixlen= vp->suffixlen) > 0 )
            {
                memcpy(&script[scriptlen],&vp->p2shscript[vp->p2shlen - vp->suffixlen],vp->suffixlen);
                scriptlen += vp->suffixlen;
            }
        }
        len += scriptlen;
    }
    return(len);
}

int32_t bitcoin_verifyvins(struct iguana_info *coin,bits256 *signedtxidp,char **signedtx,struct iguana_msgtx *msgtx,uint8_t *serialized,int32_t maxlen,struct vin_info *V,int32_t sighash)
{
    bits256 sigtxid; uint8_t *sig; struct vin_info *vp; char vpnstr[64]; int32_t plen,i,j,vini=0,flag=0,siglen,numvouts;
    numvouts = msgtx->tx_out;
    vpnstr[0] = 0;
    *signedtx = 0;
    memset(signedtxidp,0,sizeof(*signedtxidp));
    for (vini=0; vini<msgtx->tx_in; vini++)
    {
        sigtxid = bitcoin_sigtxid(coin,serialized,maxlen,msgtx,vini,msgtx->vins[vini].spendscript,msgtx->vins[vini].spendlen,sighash,vpnstr);
        if ( bits256_nonz(sigtxid) != 0 )
        {
            vp = &V[vini];
            for (j=0; j<vp->N; j++)
            {
                sig = vp->signers[j].sig;
                siglen = vp->signers[j].siglen;
                if ( bits256_nonz(vp->signers[j].privkey) != 0 )
                {
                    siglen = bitcoin_sign(coin->ctx,sig,sigtxid,vp->signers[j].privkey);
                    if ( (plen= bitcoin_pubkeylen(vp->signers[j].pubkey)) <= 0 )
                        bitcoin_pubkey33(coin->ctx,vp->signers[j].pubkey,vp->signers[j].privkey);
                    sig[siglen++] = sighash;
                    vp->signers[j].siglen = siglen;
                    for (i=0; i<siglen; i++)
                        printf("%02x",sig[i]);
                    // s2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1;
                    printf(" SIGNEDTX.[%02x] siglen.%d\n",sig[siglen-1],siglen);
                }
                if ( sig == 0 || siglen == 0 )
                {
                    memset(vp->signers[j].pubkey,0,sizeof(vp->signers[j].pubkey));
                    continue;
                }
                if ( bitcoin_verify(coin->ctx,sig,siglen-1,sigtxid,vp->signers[j].pubkey,bitcoin_pubkeylen(vp->signers[j].pubkey)) < 0 )
                {
                    
                    printf("SIG.%d.%d ERROR\n",vini,j);
                }
                else
                {
                    printf("SIG.%d.%d VERIFIED \n",vini,j);//%s (%s)\n",vini,*signedtx,jprint(txobj,1));
                    flag++;
                }
            }
        }
    }
    iguana_msgtx_Vset(coin,serialized,maxlen,msgtx,V);
    cJSON *txobj = cJSON_CreateObject();
    *signedtx = iguana_rawtxbytes(coin,txobj,msgtx);
    //printf("SIGNEDTX.(%s)\n",jprint(txobj,1));
    *signedtxidp = msgtx->txid;
    return(flag);
}

int32_t bitcoin_verifytx(struct iguana_info *coin,bits256 *signedtxidp,char **signedtx,char *rawtxstr,struct vin_info *V,int32_t numinputs)
{
    int32_t len,maxsize,retval = -1; uint8_t *serialized,*serialized2;
    struct iguana_msgtx msgtx; bits256 txid; char vpnstr[64];
    len = (int32_t)strlen(rawtxstr);
    maxsize = len + 32768;
    serialized = calloc(1,maxsize), serialized2 = calloc(1,maxsize);
    len >>= 1;
    vpnstr[0] = 0;
    decode_hex(serialized,len,rawtxstr);
    memset(&msgtx,0,sizeof(msgtx));
    if ( iguana_rwmsgtx(coin,0,0,serialized,maxsize,&msgtx,&txid,vpnstr) > 0 && numinputs == msgtx.tx_in )
    {
        if ( bitcoin_verifyvins(coin,signedtxidp,signedtx,&msgtx,serialized2,maxsize,V,SIGHASH_ALL) == 0 )
            retval = 0;
        else printf("bitcoin_verifytx: bitcoin_verifyvins error\n");
    } else printf("bitcoin_verifytx: error iguana_rwmsgtx\n");
    free(serialized), free(serialized2);
    return(retval);
}

cJSON *iguana_signtx(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,char **signedtxp,struct bitcoin_spend *spend,cJSON *txobj,cJSON *vins)
{
    int32_t i,j,m,n,plen; char *rawtxstr,*pubkeystr,*spendstr; struct vin_info *V,*vp; bits256 txid; struct iguana_waccount *wacct; struct iguana_waddress *waddr; cJSON *vitem,*vinsobj,*pubkeys;
    V = calloc(spend->numinputs,sizeof(*V));
    if ( *signedtxp != 0 )
    {
        if ( txobj != 0 )
            free_json(txobj);
        txobj = bitcoin_hex2json(coin,&txid,0,*signedtxp);
        if ( vins != 0 )
        {
            if ( jobj(txobj,"vin") != 0 )
                jdelete(txobj,"vin");
            jadd(txobj,"vin",iguana_createvins(myinfo,coin,txobj,vins));
        }
        //printf("bitcoin_hex2json (%s)\n",jprint(txobj,0));
        free(*signedtxp);
    }
    vinsobj = jarray(&n,txobj,"vin");
    for (i=0; i<spend->numinputs; i++) // N times less efficient, but for small number of inputs ok
    {
        vp = &V[i];
        if ( i < n )
        {
            if ( (vitem= jitem(vinsobj,i)) != 0 && ((spendstr= jstr(vitem,"scriptPub")) != 0 || (spendstr= jstr(vitem,"scriptPubKey")) != 0) )
            {
                vp->spendlen = (int32_t)strlen(spendstr) >> 1;
                decode_hex(vp->spendscript,vp->spendlen,spendstr);
            } else spendstr = 0;
        }
        else vitem = 0;
        vp->N = vp->M = 1;
        if ( (rawtxstr= bitcoin_json2hex(myinfo,coin,&txid,txobj,0)) != 0 )
        {
            for (j=0; j<sizeof(spend->inputs[i].privkeys)/sizeof(*spend->inputs[i].privkeys); j++)
            {
                if ( bits256_nonz(spend->inputs[i].privkeys[j]) != 0 )
                {
                    vp->signers[j].privkey = spend->inputs[i].privkeys[j];
                    bitcoin_pubkey33(coin->ctx,vp->signers[j].pubkey,vp->signers[j].privkey);
                }
                else
                {
                    vp->signers[j].pubkey[0] = 0;
                    break;
                }
            }
            if ( vitem != 0 && (pubkeys= jarray(&m,vitem,"pubkeys")) != 0 )//spend->inputs[i].numpubkeys > 0 )
            {
                for (j=0; j<sizeof(spend->inputs[i].privkeys)/sizeof(*spend->inputs[i].privkeys); j++)
                {
                    if ( j < m && (pubkeystr= jstr(jitem(pubkeys,j),0)) != 0 && is_hexstr(pubkeystr,(int32_t)strlen(pubkeystr)) > 0 )
                        decode_hex(vp->signers[j].pubkey,(int32_t)strlen(pubkeystr)>>1,pubkeystr);
                    else if ( (plen= bitcoin_pubkeylen(spend->inputs[i].pubkeys[j])) > 0 )
                        memcpy(vp->signers[j].pubkey,spend->inputs[i].pubkeys[j],plen);
                }
            }
            /*if ( spend->inputs[i].spendlen > 0 )
             {
             memcpy(vp->spendscript,spend->inputs[i].spendscript,spend->inputs[i].spendlen);
             vp->spendlen = spend->inputs[i].spendlen;
             }*/
            if ( spend->inputs[i].p2shlen > 0 )
            {
                memcpy(vp->p2shscript,spend->inputs[i].p2shscript,spend->inputs[i].p2shlen);
                vp->p2shlen = spend->inputs[i].p2shlen;
            }
            for (j=0; j<sizeof(spend->inputs[i].privkeys)/sizeof(*spend->inputs[i].privkeys); j++)
            {
                if ( vp->signers[j].coinaddr[0] == 0 && (plen= bitcoin_pubkeylen(spend->inputs[i].pubkeys[j])) > 0 )
                {
                    bitcoin_address(vp->signers[j].coinaddr,coin->chain->pubtype,spend->inputs[i].pubkeys[j],plen);
                }
            }
            if ( myinfo->expiration != 0 )
            {
                for (j=0; j<sizeof(spend->inputs[i].privkeys)/sizeof(*spend->inputs[i].privkeys); j++)
                {
                    if ( bits256_nonz(vp->signers[j].privkey) == 0 && vp->signers[j].coinaddr[0] != 0 )
                    {
                        if ( (waddr= iguana_waddresssearch(myinfo,coin,&wacct,vp->signers[j].coinaddr)) != 0 )
                            vp->signers[j].privkey = waddr->privkey;
                    }
                }
            }
            vp->sequence = spend->inputs[i].sequence;
            //printf("json2hex.(%s)\n",rawtxstr);
        }
    }
    bitcoin_verifytx(coin,txidp,signedtxp,rawtxstr,V,spend->numinputs);
    //printf("json2hex.(%s)\n",rawtxstr);
    free(rawtxstr);
    if ( *signedtxp != 0 && i != spend->numinputs )
        free(*signedtxp), *signedtxp = 0;
    free(V);
    return(txobj);
}

int32_t iguana_vininfo_create(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msgtx,cJSON *vins,int32_t numinputs,struct vin_info *V)
{
    int32_t i,plen,len = 0; struct vin_info *vp; struct iguana_waccount *wacct; struct iguana_waddress *waddr; uint32_t sigsize,pubkeysize,p2shsize,suffixlen;
    msgtx->tx_in = numinputs;
    maxsize -= (sizeof(struct iguana_msgvin) * msgtx->tx_in);
    msgtx->vins = (struct iguana_msgvin *)&serialized[maxsize];
    if ( msgtx->tx_in > 0 && msgtx->tx_in*sizeof(struct iguana_msgvin) < maxsize )
    {
        for (i=0; i<msgtx->tx_in; i++)
        {
            vp = &V[i];
            len += iguana_parsevinobj(myinfo,coin,&serialized[len],maxsize,&msgtx->vins[i],jitem(vins,i),vp);
            if ( msgtx->vins[i].spendscript == 0 )
            {
                if ( (vp->unspentind= iguana_unspentindfind(coin,vp->coinaddr,vp->spendscript,&vp->spendlen,&vp->amount,&vp->height,msgtx->vins[i].prev_hash,msgtx->vins[i].prev_vout,coin->bundlescount-1)) > 0 )
                {
                    msgtx->vins[i].spendscript = vp->spendscript;
                    msgtx->vins[i].spendlen = vp->spendlen;
                    vp->hashtype = iguana_vinscriptparse(coin,V,&sigsize,&pubkeysize,&p2shsize,&suffixlen,vp->spendscript,vp->spendlen);
                    vp->suffixlen = suffixlen;
                    printf("V %.8f (%s) spendscript.[%d]\n",dstr(vp->amount),vp->coinaddr,vp->spendlen);
                }
            }
            else
            {
                memcpy(vp->spendscript,msgtx->vins[i].spendscript,msgtx->vins[i].spendlen);
                vp->spendlen = msgtx->vins[i].spendlen;
                _iguana_calcrmd160(coin,vp);
                if ( (plen= bitcoin_pubkeylen(vp->signers[0].pubkey)) > 0 )
                    bitcoin_address(vp->coinaddr,coin->chain->pubtype,vp->signers[0].pubkey,plen);
            }
            if ( vp->coinaddr[i] != 0 && (waddr= iguana_waddresssearch(myinfo,coin,&wacct,vp->coinaddr)) != 0 )
            {
                vp->signers[0].privkey = waddr->privkey;
                if ( bitcoin_pubkeylen(waddr->pubkey) != vp->spendscript[1] || vp->spendscript[vp->spendlen-1] != 0xac )
                    memcpy(vp->signers[0].pubkey,waddr->pubkey,bitcoin_pubkeylen(waddr->pubkey));
            }
            if ( vp->M == 0 && vp->N == 0 )
                vp->M = vp->N = 1;
        }
    }
    /*for (i=0; i<msgtx->tx_out; i++)
    {
        if ( msgtx->vouts[i].pk_script != 0 )
        {
            for (j=0; j<msgtx->vouts[i].pk_scriptlen; j++)
                printf("%02x",msgtx->vouts[i].pk_script[j]);
            printf(" pk_script[%d]\n",i);
        }
    }*/
    return(len);
}

void iguana_ensure_privkey(struct supernet_info *myinfo,struct iguana_info *coin,bits256 privkey)
{
    uint8_t pubkey33[33]; struct iguana_waccount *wacct; struct iguana_waddress *waddr,addr; char coinaddr[128];
    bitcoin_pubkey33(myinfo->ctx,pubkey33,privkey);
    bitcoin_address(coinaddr,coin->chain->pubtype,pubkey33,33);
    //printf("privkey for (%s)\n",coinaddr);
    if ( myinfo->expiration != 0 && ((waddr= iguana_waddresssearch(myinfo,coin,&wacct,coinaddr)) == 0 || bits256_nonz(waddr->privkey) == 0) )
    {
        if ( waddr == 0 )
        {
            memset(&addr,0,sizeof(addr));
            iguana_waddresscalc(coin->chain->pubtype,coin->chain->wiftype,&addr,privkey);
            if ( (wacct= iguana_waccountfind(myinfo,coin,"default")) != 0 )
                waddr = iguana_waddressadd(myinfo,coin,wacct,&addr,0);
        }
        if ( waddr != 0 )
        {
            waddr->privkey = privkey;
            if ( bitcoin_priv2wif(waddr->wifstr,waddr->privkey,coin->chain->wiftype) > 0 )
            {
                waddr->wiftype = coin->chain->wiftype;
                waddr->addrtype = coin->chain->pubtype;
            }
        }
    }
}

char *_setVsigner(struct iguana_info *coin,struct vin_info *V,int32_t ind,char *pubstr,char *wifstr)
{
    uint8_t addrtype;
    decode_hex(V->signers[ind].pubkey,(int32_t)strlen(pubstr)/2,pubstr);
    bitcoin_wif2priv(&addrtype,&V->signers[ind].privkey,wifstr);
    if ( addrtype != coin->chain->pubtype )
        return(clonestr("{\"error\":\"invalid wifA\"}"));
    else return(0);
}

int32_t bitcoin_txaddspend(struct iguana_info *coin,cJSON *txobj,char *destaddress,uint64_t satoshis)
{
    uint8_t outputscript[128],addrtype,rmd160[20]; int32_t scriptlen;
    if ( bitcoin_validaddress(coin,destaddress) == 0 && satoshis != 0 )
    {
        bitcoin_addr2rmd160(&addrtype,rmd160,destaddress);
        scriptlen = bitcoin_standardspend(outputscript,0,rmd160);
        bitcoin_addoutput(coin,txobj,outputscript,scriptlen,satoshis);
        return(0);
    } else return(-1);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"


P2SH_SPENDAPI(iguana,spendmsig,activecoin,vintxid,vinvout,destaddress,destamount,destaddress2,destamount2,M,N,pubA,wifA,pubB,wifB,pubC,wifC)
{
    struct vin_info V; uint8_t p2sh_rmd160[20],serialized[2096],spendscript[32],pubkeys[3][65],*pubkeyptrs[3]; int32_t spendlen;
    char msigaddr[64],*retstr; cJSON *retjson,*txobj; struct iguana_info *active;
    bits256 signedtxid; char *signedtx;
    struct iguana_msgtx msgtx;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( (active= iguana_coinfind(activecoin)) == 0 )
        return(clonestr("{\"error\":\"activecoin isnt active\"}"));
    if ( M > N || N > 3 )
        return(clonestr("{\"error\":\"illegal M or N\"}"));
    memset(&V,0,sizeof(V));
    txobj = bitcoin_createtx(active,0);
    if ( destaddress[0] != 0 && destamount > 0. )
        bitcoin_txaddspend(active,txobj,destaddress,destamount * SATOSHIDEN);
    if ( destaddress2[0] != 0 && destamount2 > 0. )
        bitcoin_txaddspend(active,txobj,destaddress2,destamount2 * SATOSHIDEN);
    if ( pubA[0] != 0 && (retstr= _setVsigner(active,&V,0,pubA,wifA)) != 0 )
        return(retstr);
    if ( N >= 2 && pubB[0] != 0 && (retstr= _setVsigner(active,&V,1,pubB,wifB)) != 0 )
        return(retstr);
    if ( N == 3 && pubC[0] != 0 && (retstr= _setVsigner(active,&V,2,pubC,wifC)) != 0 )
        return(retstr);
    V.M = M, V.N = N, V.type = IGUANA_SCRIPT_P2SH;
    V.p2shlen = bitcoin_MofNspendscript(p2sh_rmd160,V.p2shscript,0,&V);
    spendlen = bitcoin_p2shspend(spendscript,0,p2sh_rmd160);
    if ( pubA[0] != 0 )
    {
        decode_hex(pubkeys[0],(int32_t)strlen(pubA)>>1,pubA);
        pubkeyptrs[0] = pubkeys[0];
    }
    if ( pubB[0] != 0 )
    {
        decode_hex(pubkeys[1],(int32_t)strlen(pubB)>>1,pubB);
        pubkeyptrs[1] = pubkeys[1];
    }
    if ( pubC[0] != 0 )
    {
        decode_hex(pubkeys[2],(int32_t)strlen(pubC)>>1,pubC);
        pubkeyptrs[2] = pubkeys[2];
    }
    bitcoin_addinput(active,txobj,vintxid,vinvout,0xffffffff,spendscript,spendlen,V.p2shscript,V.p2shlen,pubkeyptrs,N);
    bitcoin_address(msigaddr,active->chain->p2shtype,V.p2shscript,V.p2shlen);
    retjson = cJSON_CreateObject();
    if ( bitcoin_verifyvins(active,&signedtxid,&signedtx,&msgtx,serialized,sizeof(serialized),&V,SIGHASH_ALL) == 0 )
    {
        jaddstr(retjson,"result","msigtx");
        if ( signedtx != 0 )
            jaddstr(retjson,"signedtx",signedtx), free(signedtx);
        jaddbits256(retjson,"txid",signedtxid);
    } else jaddstr(retjson,"error","couldnt sign tx");
    jaddstr(retjson,"msigaddr",msigaddr);
    return(jprint(retjson,1));
}

STRING_ARRAY_OBJ_STRING(bitcoinrpc,signrawtransaction,rawtx,vins,privkeys,sighash)
{
    char *privkeystr,*signedtx = 0; struct vin_info *V; bits256 txid,signedtxid,privkey; int32_t len,i,n,maxsize,numinputs = 1; uint8_t *serialized=0,*serialized2=0,*serialized3=0; struct iguana_msgtx msgtx; cJSON *txobj,*item,*retjson; int uselessbitcoin_error = 0;
    retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    //printf("rawtx.(%s) vins.(%s) privkeys.(%s) sighash.(%s)\n",rawtx,jprint(vins,0),jprint(privkeys,0),sighash);
    if ( sighash == 0 || sighash[0] == 0 )
        sighash = "ALL";
    if ( strcmp(sighash,"ALL") != 0 )
        jaddstr(retjson,"error","only sighash all (ALL) supported for now");
    maxsize = 65536;
    if ( rawtx != 0 && rawtx[0] != 0 && (len= (int32_t)strlen(rawtx)>>1) < maxsize )
    {
        serialized = malloc(maxsize);
        serialized2 = malloc(maxsize);
        serialized3 = malloc(maxsize);
        memset(&msgtx,0,sizeof(msgtx));
        decode_hex(serialized,len,rawtx);
        if ( (txobj= bitcoin_hex2json(coin,&txid,&msgtx,rawtx)) != 0 )
        {
            char *checkstr;
            //printf("txobj.(%s)\n",jprint(txobj,0));
            if ( (checkstr= bitcoin_json2hex(myinfo,coin,&txid,txobj,0)) != 0 )
            {
                if ( strcmp(rawtx,checkstr) != 0 )
                {
                    printf("RAW.(%s) ->\nNEW.(%s)\n",rawtx,checkstr);
                    free_json(txobj);
                    free(checkstr);
                    free(serialized);
                    free(serialized2);
                    free(serialized3);
                    jaddstr(retjson,"error",uselessbitcoin_error != 0 ? "-22" : "hex2json -> json2hex error");
                    return(jprint(retjson,1));
                }
                free(checkstr);
            }
            free_json(txobj);
        }
        if ( (numinputs= cJSON_GetArraySize(vins)) > 0 )
            V = calloc(numinputs,sizeof(*V));
        memset(&msgtx,0,sizeof(msgtx));
        if ( iguana_rwmsgtx(coin,0,0,serialized,maxsize,&msgtx,&txid,"") > 0 && numinputs == msgtx.tx_in )
        {
            if ( (n= cJSON_GetArraySize(privkeys)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(privkeys,i);
                    privkeystr = jstr(item,0);
                    privkey = iguana_str2priv(myinfo,coin,privkeystr);
                    if ( bits256_nonz(privkey) != 0 )
                        iguana_ensure_privkey(myinfo,coin,privkey);
                }
            }
            signedtx = 0;
            iguana_vininfo_create(myinfo,coin,serialized2,maxsize,&msgtx,vins,numinputs,V);
            bitcoin_verifyvins(coin,&signedtxid,&signedtx,&msgtx,serialized3,maxsize,V,SIGHASH_ALL);
            free(V);
            if ( signedtx != 0 )
            {
                jaddstr(retjson,"result",signedtx);
                free(signedtx);
            } else jaddstr(retjson,"error",uselessbitcoin_error != 0 ? "-22" : "no transaction from verifyvins");
        }
        else
        {
            /*char *testscript = "76a914010966776006953d5567439e5e39f86a0d273bee88ac";
            uint8_t script[256]; bits256 sigtxid; int32_t scriptlen = (int32_t)strlen(testscript) >> 1;
            decode_hex(script,scriptlen,testscript);
            sigtxid = bitcoin_sigtxid(coin,serialized,sizeof(serialized),&msgtx,0,msgtx.vins[0].spendscript,msgtx.vins[0].spendlen,SIGHASH_ALL,"");
            char str[65]; printf("sigtxid.(%s)\n",bits256_str(str,sigtxid));*/
            jaddstr(retjson,"error",uselessbitcoin_error != 0 ? "-22" : "couldnt load serialized tx or mismatched numinputs");
        }
        free(serialized);
        free(serialized2);
        free(serialized3);
    } else jaddstr(retjson,"error",uselessbitcoin_error != 0 ? "-22" : "no rawtx or rawtx too big");
    return(jprint(retjson,1));
}

#include "../includes/iguana_apiundefs.h"

