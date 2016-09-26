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

// make sure coinbase outputs are matured

int32_t iguana_vinparse(struct iguana_info *coin,int32_t rwflag,uint8_t *serialized,struct iguana_msgvin *msg)
{
    int32_t p2shlen,len = 0; uint32_t tmp;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
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
    if ( 0 )
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
        if ( 0 )
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

cJSON *iguana_vinjson(struct iguana_info *coin,struct iguana_msgvin *vin,bits256 sigtxid)
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
        if ( bits256_nonz(sigtxid) != 0 )
            jaddbits256(json,"sigtxid",sigtxid);
        if ( vin->scriptlen > 0 && vin->vinscript != 0 ) // sigs
            iguana_addscript(coin,json,vin->vinscript,vin->scriptlen,"scriptSig");
        if ( vin->userdatalen > 0 && vin->userdata != 0 )
            iguana_addscript(coin,json,vin->userdata,vin->userdatalen,"userdata");
        if ( vin->p2shlen > 0 && vin->redeemscript != 0 )
            iguana_addscript(coin,json,vin->redeemscript,vin->p2shlen,"redeemScript");
        if ( vin->spendlen > 0 && vin->spendscript != 0 )
            iguana_addscript(coin,json,vin->spendscript,vin->spendlen,"scriptPubKey");
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

int32_t iguana_parsevinobj(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_msgvin *vin,cJSON *vinobj,struct vin_info *V)
{
    struct iguana_outpoint outpt; struct iguana_waddress *waddr; struct iguana_waccount *wacct; uint8_t lastbyte,spendscript[8192]; uint32_t tmp=0; int32_t i,n,starti,spendlen,suppress_pubkeys,siglen,plen,m,endi,rwflag=1,len = 0; char *userdata=0,*pubkeystr,*hexstr = 0,*redeemstr = 0,*spendstr = 0; cJSON *scriptjson = 0,*obj,*pubkeysjson = 0;
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
        vin->prev_vout = jint(vinobj,"vout");
        if ( (scriptjson= jobj(vinobj,"scriptSig")) != 0 )
            hexstr = jstr(scriptjson,"hex");
        if ( ((spendstr= jstr(vinobj,"scriptPub")) == 0 && (spendstr= jstr(vinobj,"scriptPubKey")) == 0) || is_hexstr(spendstr,(int32_t)strlen(spendstr)) <= 0 )
        {
            if ( (obj= jobj(vinobj,"scriptPub")) != 0 || (obj= jobj(vinobj,"scriptPubKey")) != 0 )
            {
                spendstr = jstr(obj,"hex");
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
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(vin->prev_hash),vin->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(vin->prev_vout),&vin->prev_vout);
    if ( V != 0 )
    {
        V->suppress_pubkeys = suppress_pubkeys;
        if ( vin->vinscript == 0 && V->spendlen == 0 )
        {
            if ( iguana_RTunspentindfind(myinfo,coin,&outpt,V->coinaddr,spendscript,&spendlen,&V->amount,&V->height,vin->prev_hash,vin->prev_vout,coin->bundlescount-1,0) == 0 )
            {
                V->unspentind = outpt.unspentind;
                if ( V->coinaddr[0] != 0 && (waddr= iguana_waddresssearch(myinfo,&wacct,V->coinaddr)) != 0 )
                {
                    memcpy(V->signers[0].pubkey,waddr->pubkey,bitcoin_pubkeylen(waddr->pubkey));
                }
                //printf("V %.8f (%s) spendscript.[%d]\n",dstr(V->amount),V->coinaddr,V->spendlen);
            }
            if ( spendlen != 0 && V->spendlen == 0 )
            {
                V->spendlen = spendlen;
                memcpy(V->spendscript,spendscript,spendlen);
            }
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
                {
                    int32_t j;
                    for (j=0; j<siglen; j++)
                        printf("%02x",serialized[len + m + j]);
                    printf(" (%d)\n",siglen);
                }
                m += siglen;
                i++;
            }
            if ( m != n )
                printf("ERROR: (%s) len.%d n.%d i.%d\n",hexstr,m,n,i);
        }
        len += n;
    } //else printf("iguana_parsevinobj: hex script missing (%s)\n",jprint(vinobj,0));
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
                if ( V != 0 )
                    memcpy(V->signers[i].pubkey,&vin->vinscript[vin->scriptlen],plen);
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

int32_t iguana_parsevoutobj(struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_msgvout *vout,cJSON *voutobj)
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

cJSON *iguana_voutjson(struct iguana_info *coin,struct iguana_msgvout *vout,int32_t txi,bits256 txid)
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

bits256 bitcoin_sigtxid(struct iguana_info *coin,int32_t height,uint8_t *serialized,int32_t maxlen,struct iguana_msgtx *msgtx,int32_t vini,uint8_t *spendscript,int32_t spendlen,int32_t hashtype,char *vpnstr,int32_t suppress_pubkeys)
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
        }
        else
        {
            dest.vins[i].vinscript = (uint8_t *)"";
            dest.vins[i].scriptlen = 0;
        }
        dest.vins[i].p2shlen = 0;
        dest.vins[i].redeemscript = 0;
    }
    len = iguana_rwmsgtx(coin,height,1,0,serialized,maxlen,&dest,&txid,vpnstr,0,0,0,suppress_pubkeys);
    //for (i=0; i<len; i++)
    //    printf("%02x",serialized[i]);
    //printf(" <- sigtx\n");
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

void iguana_vinobjset(struct iguana_msgvin *vin,cJSON *item,uint8_t *spendscript,int32_t maxsize)
{
    char *redeemstr,*hexstr; cJSON *sobj;
    if ( (redeemstr= jstr(item,"redeemScript")) != 0 && is_hexstr(redeemstr,0) > 0 )
        vin->p2shlen = (int32_t)strlen(redeemstr) >> 1;
    if ( (sobj= jobj(item,"scriptPubKey")) != 0 && (hexstr= jstr(sobj,"hex")) != 0 && is_hexstr(hexstr,0) > 0 && (vin->spendlen == 0 || vin->spendscript == 0) )
    {
        vin->spendlen = (int32_t)strlen(hexstr) >> 1;
        if ( vin->spendlen < maxsize )
        {
            if ( vin->spendscript == 0 )
                vin->spendscript = spendscript;
            decode_hex(vin->spendscript,vin->spendlen,hexstr);
        }
    }
}

int32_t iguana_rwmsgtx(struct iguana_info *coin,int32_t height,int32_t rwflag,cJSON *json,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,bits256 *txidp,char *vpnstr,uint8_t *extraspace,int32_t extralen,cJSON *vins,int32_t suppress_pubkeys)
{
    int32_t i,n,len = 0,extraused=0; uint8_t spendscript[8192],*txstart = serialized,*sigser=0; char txidstr[65]; cJSON *vinarray=0,*voutarray=0; bits256 sigtxid;
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
    if ( coin->chain->isPoS != 0 )
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
        if ( (n= iguana_vinparse(coin,rwflag,&serialized[len],&msg->vins[i])) < 0 )
            return(-1);
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
            printf("invalid tx_out.%d len.%d vs maxsize.%d n.%d\n",msg->tx_out,len,maxsize,n);
            return(-1);
        }
        if ( voutarray != 0 )
            jaddi(voutarray,iguana_voutjson(coin,&msg->vouts[i],i,*txidp));
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    //printf("lock_time.%08x len.%d\n",msg->lock_time,len);
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
    if ( sigser != 0 && vinarray != 0 )
    {
        for (i=0; i<msg->tx_in; i++)
        {
            memset(sigtxid.bytes,0,sizeof(sigtxid));
            if ( vins != 0 && jitem(vins,i) != 0 )
            {
                iguana_vinobjset(&msg->vins[i],jitem(vins,i),spendscript,sizeof(spendscript));
                sigtxid = bitcoin_sigtxid(coin,height,sigser,maxsize*2,msg,i,msg->vins[i].spendscript,msg->vins[i].spendlen,SIGHASH_ALL,vpnstr,suppress_pubkeys);
                //printf("after vini.%d vinscript.%p spendscript.%p spendlen.%d (%s)\n",i,msg->vins[i].vinscript,msg->vins[i].spendscript,msg->vins[i].spendlen,jprint(jitem(vins,i),0));
                jaddi(vinarray,iguana_vinjson(coin,&msg->vins[i],sigtxid));
                if ( msg->vins[i].spendscript == spendscript )
                    msg->vins[i].spendscript = 0;
            } else jaddi(vinarray,iguana_vinjson(coin,&msg->vins[i],sigtxid));
        }
        free(sigser);
        jadd(json,"vin",vinarray);
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

bits256 iguana_parsetxobj(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *txstartp,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,cJSON *txobj,struct vin_info *V)
{
    int32_t i,numvins,numvouts,len = 0,rwflag=1; cJSON *array=0; bits256 txid; char vpnstr[64];
    memset(&txid,0,sizeof(txid));
    memset(msg,0,sizeof(*msg));
    *txstartp = 0;
    if ( txobj == 0 )
        return(txid);
    vpnstr[0] = 0;
    if ( (msg->version= juint(txobj,"version")) == 0 )
        msg->version = 1;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( coin->chain->isPoS != 0 )
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
                //printf("parsetxobj vinobj.%d starts offset.%d\n",i,len);
                len += iguana_parsevinobj(myinfo,coin,&serialized[len],maxsize,&msg->vins[i],jitem(array,i),V!=0?&V[i]:0);
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
                len += iguana_parsevoutobj(coin,&serialized[len],maxsize,&msg->vouts[i],jitem(array,i));
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

char *iguana_rawtxbytes(struct iguana_info *coin,int32_t height,cJSON *json,struct iguana_msgtx *msgtx,int32_t suppress_pubkeys)
{
    int32_t n; char *txbytes = 0,vpnstr[64]; uint8_t *serialized;
    serialized = malloc(IGUANA_MAXPACKETSIZE);
    vpnstr[0] = 0;
    //char str[65]; printf("%d of %d: %s\n",i,msg.txn_count,bits256_str(str,tx.txid));
    if ( (n= iguana_rwmsgtx(coin,height,1,json,serialized,IGUANA_MAXPACKETSIZE,msgtx,&msgtx->txid,vpnstr,0,0,0,suppress_pubkeys)) > 0 )
    {
        txbytes = malloc(n*2+1);
        init_hexbytes_noT(txbytes,serialized,n);
    }
    free(serialized);
    return(txbytes);
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

cJSON *bitcoin_data2json(struct iguana_info *coin,int32_t height,bits256 *txidp,struct iguana_msgtx *msgtx,uint8_t *extraspace,int32_t extralen,uint8_t *serialized,int32_t len,cJSON *vins,int32_t suppress_pubkeys)
{
    int32_t n; char vpnstr[64]; struct iguana_msgtx M; cJSON *txobj;
    if ( coin == 0 || serialized == 0 )
        return(0);
    txobj = cJSON_CreateObject();
    if ( msgtx == 0 )
        msgtx = &M;
    memset(msgtx,0,sizeof(M));
    vpnstr[0] = 0;
    memset(txidp,0,sizeof(*txidp));
    if ( (n= iguana_rwmsgtx(coin,height,0,txobj,serialized,len,msgtx,txidp,vpnstr,extraspace,extralen,vins,suppress_pubkeys)) <= 0 )
    {
        printf("errortxobj.(%s)\n",jprint(txobj,0));
        free_json(txobj);
        txobj = cJSON_CreateObject();
        jaddstr(txobj,"error","couldnt decode transaction");
        jaddstr(txobj,"coin",coin->symbol);
    }
    if ( n != len )
    {
        int32_t i;
        for (i=0; i<=len; i++)
            printf("%02x",serialized[i]);
        printf(" data2json n.%d vs len.%d\n",n,len);
    }
    return(txobj);
}

cJSON *bitcoin_hex2json(struct iguana_info *coin,int32_t height,bits256 *txidp,struct iguana_msgtx *msgtx,char *txbytes,uint8_t *extraspace,int32_t extralen,uint8_t *origserialized,cJSON *vins,int32_t suppress_pubkeys)
{
    int32_t len; uint8_t *serialized; cJSON *txobj;
    if ( coin == 0 || txbytes == 0 )
        return(0);
    len = (int32_t)strlen(txbytes) >> 1;
    if ( (serialized= origserialized) == 0 )
        serialized = calloc(1,len+4096);
    decode_hex(serialized,len,txbytes);
    txobj = bitcoin_data2json(coin,height,txidp,msgtx,extraspace,extralen,serialized,len,vins,suppress_pubkeys);
    if ( serialized != origserialized )
        free(serialized);
    return(txobj);
}

int32_t iguana_msgtx_Vset(struct iguana_info *coin,uint8_t *serialized,int32_t maxlen,struct iguana_msgtx *msgtx,struct vin_info *V)
{
    int32_t vini,j,scriptlen,p2shlen,userdatalen,siglen,plen,need_op0=0,len = 0; uint8_t *script,*redeemscript=0,*userdata=0; struct vin_info *vp;
    for (vini=0; vini<msgtx->tx_in; vini++)
    {
        vp = &V[vini];
        if ( (userdatalen= vp->userdatalen) == 0 )
        {
            userdatalen = vp->userdatalen = msgtx->vins[vini].userdatalen;
            userdata = msgtx->vins[vini].userdata;
        } else userdata = vp->userdata;
        if ( (p2shlen= vp->p2shlen) == 0 )
        {
            p2shlen = vp->p2shlen = msgtx->vins[vini].p2shlen;
            redeemscript = msgtx->vins[vini].redeemscript;
        }
        else
        {
            redeemscript = vp->p2shscript;
            msgtx->vins[vini].redeemscript = redeemscript;
        }
        if ( msgtx->vins[vini].spendlen > 33 && msgtx->vins[vini].spendscript[msgtx->vins[vini].spendlen - 1] == SCRIPT_OP_CHECKMULTISIG )
        {
            need_op0 = 1;
            printf("found multisig spendscript\n");
        }
        if ( redeemscript != 0 && p2shlen > 33 && redeemscript[p2shlen - 1] == SCRIPT_OP_CHECKMULTISIG )
        {
            need_op0 = 1;
            printf("found multisig redeemscript\n");
        }
        msgtx->vins[vini].vinscript = script = &serialized[len];
        msgtx->vins[vini].vinscript[0] = 0;
        scriptlen = need_op0;
        for (j=0; j<vp->N; j++)
        {
            if ( (siglen= vp->signers[j].siglen) > 0 )
            {
                script[scriptlen++] = siglen;
                memcpy(&script[scriptlen],vp->signers[j].sig,siglen);
                scriptlen += siglen;
            }
        }
        msgtx->vins[vini].scriptlen = scriptlen;
        if ( vp->suppress_pubkeys == 0 && (vp->N > 1 || bitcoin_pubkeylen(&vp->spendscript[1]) != vp->spendscript[0] || vp->spendscript[vp->spendlen-1] != 0xac) )
        {
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
        }
        if ( userdatalen != 0 )
        {
            memcpy(&script[scriptlen],userdata,userdatalen);
            msgtx->vins[vini].userdata = &script[scriptlen];
            msgtx->vins[vini].userdatalen = userdatalen;
            scriptlen += userdatalen;
        }
        //printf("USERDATALEN.%d scriptlen.%d redeemlen.%d\n",userdatalen,scriptlen,p2shlen);
        if ( p2shlen != 0 )
        {
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
            msgtx->vins[vini].p2shlen = p2shlen;
            memcpy(&script[scriptlen],redeemscript,p2shlen);
            scriptlen += p2shlen;
        }
        len += scriptlen;
    }
    if ( 0 )
    {
        int32_t i; for (i=0; i<len; i++)
            printf("%02x",script[i]);
        printf(" <-script len.%d scriptlen.%d p2shlen.%d user.%d\n",len,scriptlen,p2shlen,userdatalen);
    }
    return(len);
}

int32_t bitcoin_verifyvins(struct iguana_info *coin,int32_t height,bits256 *signedtxidp,char **signedtx,struct iguana_msgtx *msgtx,uint8_t *serialized,int32_t maxlen,struct vin_info *V,uint32_t sighash,int32_t signtx,int32_t suppress_pubkeys)
{
    bits256 sigtxid; uint8_t *sig; struct vin_info *vp; char vpnstr[64]; int32_t complete=0,plen,j,vini=0,flag=0,siglen,numvouts,numsigs;
    numvouts = msgtx->tx_out;
    vpnstr[0] = 0;
    *signedtx = 0;
    memset(signedtxidp,0,sizeof(*signedtxidp));
    for (vini=0; vini<msgtx->tx_in; vini++)
    {
        sigtxid = bitcoin_sigtxid(coin,height,serialized,maxlen,msgtx,vini,msgtx->vins[vini].spendscript,msgtx->vins[vini].spendlen,sighash,vpnstr,suppress_pubkeys);
        if ( bits256_nonz(sigtxid) != 0 )
        {
            vp = &V[vini];
            vp->sigtxid = sigtxid;
            for (j=numsigs=0; j<vp->N; j++)
            {
                sig = vp->signers[j].sig;
                siglen = vp->signers[j].siglen;
                if ( signtx != 0 && bits256_nonz(vp->signers[j].privkey) != 0 )
                {
                    siglen = bitcoin_sign(coin->ctx,coin->symbol,sig,sigtxid,vp->signers[j].privkey,0);
                    if ( (plen= bitcoin_pubkeylen(vp->signers[j].pubkey)) <= 0 )
                        bitcoin_pubkey33(coin->ctx,vp->signers[j].pubkey,vp->signers[j].privkey);
                    sig[siglen++] = sighash;
                    vp->signers[j].siglen = siglen;
                    int32_t i; for (i=0; i<siglen; i++)
                        printf("%02x",sig[i]);
                    printf(" sig, ");
                    for (i=0; i<plen; i++)
                        printf("%02x",vp->signers[j].pubkey[i]);
                    // s2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1;
                    char str[65]; printf(" SIGNEDTX.[%02x] siglen.%d priv.%s\n",sig[siglen-1],siglen,bits256_str(str,vp->signers[j].privkey));
                }
                if ( sig == 0 || siglen == 0 )
                {
                    memset(vp->signers[j].pubkey,0,sizeof(vp->signers[j].pubkey));
                    continue;
                }
                if ( bitcoin_verify(coin->ctx,sig,siglen-1,sigtxid,vp->signers[j].pubkey,bitcoin_pubkeylen(vp->signers[j].pubkey)) < 0 )
                {
                    
                    //printf("SIG.%d.%d ERROR siglen.%d\n",vini,j,siglen);
                }
                else
                {
                    flag++;
                    numsigs++;
                    /*int32_t z;
                    for (z=0; z<siglen-1; z++)
                        printf("%02x",sig[z]);
                    printf(" <- sig[%d]n\n",j);
                    for (z=0; z<33; z++)
                        printf("%02x",vp->signers[j].pubkey[z]);*/
                    //printf(" <- pub, SIG.%d.%d VERIFIED numsigs.%d vs M.%d\n",vini,j,numsigs,vp->M);
                }
            }
            if ( numsigs >= vp->M )
                complete = 1;
        }
    } //0398a4cb9f6ea7c52a4e27455028a95e2e4e397a110fb75f072c2c58a8bdcb
    iguana_msgtx_Vset(coin,serialized,maxlen,msgtx,V);
    cJSON *txobj = cJSON_CreateObject();
    *signedtx = iguana_rawtxbytes(coin,height,txobj,msgtx,suppress_pubkeys);
    //printf("SIGNEDTX.(%s)\n",jprint(txobj,1));
    *signedtxidp = msgtx->txid;
    return(complete);
}

int32_t iguana_vininfo_create(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msgtx,cJSON *vins,int32_t numinputs,struct vin_info *V)
{
    struct iguana_outpoint outpt; int32_t i,plen,finalized = 1,len = 0; struct vin_info *vp; struct iguana_waccount *wacct; struct iguana_waddress *waddr; uint32_t sigsize,pubkeysize,p2shsize,userdatalen;
    msgtx->tx_in = numinputs;
    maxsize -= (sizeof(struct iguana_msgvin) * msgtx->tx_in);
    msgtx->vins = (struct iguana_msgvin *)&serialized[maxsize];
    memset(msgtx->vins,0,sizeof(struct iguana_msgvin) * msgtx->tx_in);
    if ( msgtx->tx_in > 0 && msgtx->tx_in*sizeof(struct iguana_msgvin) < maxsize )
    {
        for (i=0; i<msgtx->tx_in; i++)
        {
            vp = &V[i];
            //printf("VINS.(%s)\n",jprint(jitem(vins,i),0));
            len += iguana_parsevinobj(myinfo,coin,&serialized[len],maxsize,&msgtx->vins[i],jitem(vins,i),vp);
            if ( msgtx->vins[i].sequence < IGUANA_SEQUENCEID_FINAL )
                finalized = 0;
            if ( msgtx->vins[i].spendscript == 0 )
            {
                if ( iguana_RTunspentindfind(myinfo,coin,&outpt,vp->coinaddr,vp->spendscript,&vp->spendlen,&vp->amount,&vp->height,msgtx->vins[i].prev_hash,msgtx->vins[i].prev_vout,coin->bundlescount-1,0) == 0 )
                {
                    vp->unspentind = outpt.unspentind;
                    msgtx->vins[i].spendscript = vp->spendscript;
                    msgtx->vins[i].spendlen = vp->spendlen;
                    vp->hashtype = iguana_vinscriptparse(coin,vp,&sigsize,&pubkeysize,&p2shsize,&userdatalen,vp->spendscript,vp->spendlen);
                    vp->userdatalen = userdatalen;
                    printf("V %.8f (%s) spendscript.[%d] userdatalen.%d\n",dstr(vp->amount),vp->coinaddr,vp->spendlen,userdatalen);
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
            if ( vp->M == 0 && vp->N == 0 )
                vp->M = vp->N = 1;
            if ( vp->coinaddr[i] != 0 && (waddr= iguana_waddresssearch(myinfo,&wacct,vp->coinaddr)) != 0 )
            {
                vp->signers[0].privkey = waddr->privkey;
                if ( (plen= bitcoin_pubkeylen(waddr->pubkey)) != vp->spendscript[1] || vp->spendscript[vp->spendlen-1] != 0xac )
                {
                    if ( plen > 0 && plen < sizeof(vp->signers[0].pubkey) )
                        memcpy(vp->signers[0].pubkey,waddr->pubkey,plen);
                }
            }
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
    return(finalized);
}

void iguana_ensure_privkey(struct supernet_info *myinfo,struct iguana_info *coin,bits256 privkey)
{
    uint8_t pubkey33[33]; struct iguana_waccount *wacct; struct iguana_waddress *waddr,addr; char coinaddr[128];
    bitcoin_pubkey33(myinfo->ctx,pubkey33,privkey);
    bitcoin_address(coinaddr,coin->chain->pubtype,pubkey33,33);
    //printf("privkey for (%s)\n",coinaddr);
    if ( myinfo->expiration != 0 && ((waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) == 0 || bits256_nonz(waddr->privkey) == 0) )
    {
        if ( waddr == 0 )
        {
            memset(&addr,0,sizeof(addr));
            iguana_waddresscalc(myinfo,coin->chain->pubtype,coin->chain->wiftype,&addr,privkey);
            if ( (wacct= iguana_waccountfind(myinfo,"default")) != 0 )
                waddr = iguana_waddressadd(myinfo,coin,wacct,&addr,0);
        }
        if ( waddr != 0 )
        {
            waddr->privkey = privkey;
            if ( bitcoin_priv2wif(waddr->wifstr,waddr->privkey,coin->chain->wiftype) > 0 )
            {
                if ( 0 && waddr->wiftype != coin->chain->wiftype )
                    printf("ensurepriv warning: mismatched wiftype %02x != %02x\n",waddr->wiftype,coin->chain->wiftype);
                if ( 0 && waddr->addrtype != coin->chain->pubtype )
                    printf("ensurepriv warning: mismatched addrtype %02x != %02x\n",waddr->addrtype,coin->chain->pubtype);
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
        bitcoin_txoutput(txobj,outputscript,scriptlen,satoshis);
        return(0);
    } else return(-1);
}

cJSON *bitcoin_txscript(struct iguana_info *coin,char *asmstr,char **vardata,int32_t numvars)
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
        iguana_expandscript(coin,scriptstr,maxlen,script,scriptlen);
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

cJSON *bitcoin_txinput(struct iguana_info *coin,cJSON *txobj,bits256 txid,int32_t vout,uint32_t sequenceid,uint8_t *spendscript,int32_t spendlen,uint8_t *redeemscript,int32_t p2shlen,uint8_t *pubkeys[],int32_t numpubkeys)
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

cJSON *bitcoin_txcreate(int32_t isPoS,int64_t locktime,uint32_t txversion)
{
    cJSON *json = cJSON_CreateObject();
    jaddnum(json,"version",txversion);
    jaddnum(json,"locktime",locktime);
    if ( isPoS != 0 )
        jaddnum(json,"timestamp",time(NULL));
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

int32_t iguana_interpreter(struct iguana_info *coin,cJSON *logarray,int64_t nLockTime,struct vin_info *V,int32_t numvins)
{
    uint8_t script[IGUANA_MAXSCRIPTSIZE],*activescript; char str[IGUANA_MAXSCRIPTSIZE*2+1]; int32_t vini,scriptlen,activescriptlen,errs = 0; cJSON *spendscript,*item;
    for (vini=0; vini<numvins; vini++)
    {
        if ( V[vini].p2shlen > 0 )
        {
            activescript = V[vini].p2shscript;
            activescriptlen = V[vini].p2shlen;
        }
        else
        {
            activescript = V[vini].spendscript;
            activescriptlen = V[vini].spendlen;
        }
        spendscript = iguana_spendasm(coin,activescript,activescriptlen);
        if ( activescriptlen < 16 )
            continue;
        //printf("interpreter.(%s)\n",jprint(spendscript,0));
        if ( (scriptlen= bitcoin_assembler(coin,logarray,script,spendscript,1,nLockTime,&V[vini])) < 0 )
        {
            errs++;
        }
        else if ( scriptlen != activescriptlen || memcmp(script,activescript,scriptlen) != 0 )
        {
            if ( logarray != 0 )
            {
                item = cJSON_CreateObject();
                jaddstr(item,"error","script reconstruction failed");
                init_hexbytes_noT(str,activescript,activescriptlen);
                jaddstr(item,"original",str);
                init_hexbytes_noT(str,script,scriptlen);
                jaddstr(item,"reconstructed",str);
                jaddi(logarray,item);
            } else printf("scriptlen mismatch.%d vs %d or miscompare\n",scriptlen,V[vini].spendlen);
            errs++;
        }
    }
    if ( errs != 0 )
        return(-errs);
    if ( logarray != 0 )
    {
        item = cJSON_CreateObject();
        jaddstr(item,"result","success");
        jaddi(logarray,item);
    }
    return(0);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"


P2SH_SPENDAPI(iguana,spendmsig,activecoin,vintxid,vinvout,destaddress,destamount,destaddress2,destamount2,M,N,pubA,wifA,pubB,wifB,pubC,wifC)
{
    struct vin_info V; uint8_t p2sh_rmd160[20],serialized[2096],spendscript[32],pubkeys[3][65],*pubkeyptrs[3]; int32_t spendlen,height = 0;
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
    txobj = bitcoin_txcreate(active->chain->isPoS,0,coin->chain->normal_txversion);
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
    bitcoin_txinput(active,txobj,vintxid,vinvout,0xffffffff,spendscript,spendlen,V.p2shscript,V.p2shlen,pubkeyptrs,N);
    bitcoin_address(msigaddr,active->chain->p2shtype,V.p2shscript,V.p2shlen);
    retjson = cJSON_CreateObject();
    if ( bitcoin_verifyvins(active,height,&signedtxid,&signedtx,&msgtx,serialized,sizeof(serialized),&V,SIGHASH_ALL,1,V.suppress_pubkeys) == 0 )
    {
        jaddstr(retjson,"result","msigtx");
        if ( signedtx != 0 )
            jaddstr(retjson,"signedtx",signedtx), free(signedtx);
        jaddbits256(retjson,"txid",signedtxid);
    } else jaddstr(retjson,"error","couldnt sign tx");
    jaddstr(retjson,"msigaddr",msigaddr);
    return(jprint(retjson,1));
}

int32_t iguana_signrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,int32_t height,struct iguana_msgtx *msgtx,char **signedtxp,bits256 *signedtxidp,struct vin_info *V,int32_t numinputs,char *rawtx,cJSON *vins,cJSON *privkeys)
{
    uint8_t *serialized,*serialized2,*serialized3,*serialized4,*extraspace; int32_t finalized,i,len,n,maxsize,complete = 0,extralen = 65536; char *checkstr,*privkeystr,*signedtx = 0; bits256 privkey,txid; cJSON *item; cJSON *txobj = 0;
    maxsize = 1000000;
    if ( rawtx != 0 && rawtx[0] != 0 && (len= (int32_t)strlen(rawtx)>>1) < maxsize )
    {
        serialized = malloc(maxsize);
        serialized2 = malloc(maxsize);
        serialized3 = malloc(maxsize);
        serialized4 = malloc(maxsize);
        extraspace = malloc(extralen);
        memset(msgtx,0,sizeof(*msgtx));
        decode_hex(serialized,len,rawtx);
        if ( (txobj= bitcoin_hex2json(coin,height,&txid,msgtx,rawtx,extraspace,extralen,serialized4,vins,V->suppress_pubkeys)) != 0 )
        {
            //if ( vins != 0 )
            //    printf("vins.(%s)\n",jprint(vins,0));
            if ( jobj(txobj,"error") != 0 )
            {
                printf("txobj.(%s)\n",jprint(txobj,0));
            }
            if ( 0 && (checkstr= bitcoin_json2hex(myinfo,coin,&txid,txobj,V)) != 0 ) // no guarantee of identical regen
            {
                if ( strcmp(rawtx,checkstr) != 0 )
                {
                    printf("RAW.(%s) ->\nNEW.(%s)\n",rawtx,checkstr);
                    //free_json(txobj);
                    //free(checkstr);
                    //free(serialized), free(serialized2), free(serialized3), free(serialized4);
                    //free(extraspace);
                    //return(-2);
                }
                free(checkstr);
            }
        }
        if ( (numinputs= cJSON_GetArraySize(vins)) > 0 )
        {
            memset(msgtx,0,sizeof(*msgtx));
            if ( iguana_rwmsgtx(coin,height,0,0,serialized,maxsize,msgtx,&txid,"",extraspace,65536,vins,V->suppress_pubkeys) > 0 && numinputs == msgtx->tx_in )
            {
                if ( (n= cJSON_GetArraySize(privkeys)) > 0 )
                {
                    for (i=0; i<n; i++)
                    {
                        item = jitem(privkeys,i);
                        privkeystr = jstr(item,0);
                        privkey = iguana_str2priv(myinfo,coin,privkeystr);
                        V->signers[i].privkey = privkey;
                        if ( i < numinputs )
                            V[i].signers[0].privkey = privkey;
                        if ( bits256_nonz(privkey) != 0 )
                            iguana_ensure_privkey(myinfo,coin,privkey);
                        if ( V->suppress_pubkeys == 0 && bitcoin_pubkeylen(V->signers[i].pubkey) <= 0 )
                        {
                            bitcoin_pubkey33(myinfo->ctx,V->signers[i].pubkey,privkey);
                            if ( i < numinputs )
                                memcpy(V[i].signers[0].pubkey,V->signers[i].pubkey,bitcoin_pubkeylen(V->signers[i].pubkey));
                        }
                    }
                }
                finalized = iguana_vininfo_create(myinfo,coin,serialized2,maxsize,msgtx,vins,numinputs,V);
                if ( (complete= bitcoin_verifyvins(coin,height,signedtxidp,&signedtx,msgtx,serialized3,maxsize,V,SIGHASH_ALL,1,V->suppress_pubkeys)) > 0 && signedtx != 0 )
                {
                    int32_t tmp;
                    if ( (tmp= iguana_interpreter(coin,0,iguana_lockval(finalized,jint(txobj,"locktime")),V,numinputs)) < 0 )
                    {
                        printf("iguana_interpreter %d error.(%s)\n",tmp,signedtx);
                        complete = 0;
                    }
                }
            }
        }
        free(extraspace);
        free(serialized), free(serialized2), free(serialized3), free(serialized4);
    } else return(-1);
    if ( txobj != 0 )
        free_json(txobj);
    *signedtxp = signedtx;
    return(complete);
}

STRING_ARRAY_OBJ_STRING(bitcoinrpc,signrawtransaction,rawtx,vins,privkeys,sighash)
{
    char *signedtx = 0; struct vin_info *V; bits256 signedtxid; int32_t complete,numinputs = 1; struct iguana_msgtx msgtx; cJSON *retjson; int uselessbitcoin_error = 0;
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
    if ( (numinputs= cJSON_GetArraySize(vins)) > 0 )
    {
        V = calloc(numinputs,sizeof(*V));
        memset(&msgtx,0,sizeof(msgtx));
        if ( (complete= iguana_signrawtransaction(myinfo,coin,coin->blocks.hwmchain.height,&msgtx,&signedtx,&signedtxid,V,numinputs,rawtx,vins,privkeys)) >= 0 )
        {
            if ( signedtx != 0 )
            {
                jaddstr(retjson,"result",signedtx);
                jadd(retjson,"complete",complete!=0?jtrue():jfalse());
                free(signedtx);
            } else jaddstr(retjson,"error",uselessbitcoin_error != 0 ? "-22" : "no transaction from verifyvins");
        }
        else if ( complete == -2 )
            jaddstr(retjson,"error",uselessbitcoin_error != 0 ? "-22" : "hex2json -> json2hex error");
        else if ( complete == -1 )
            jaddstr(retjson,"error",uselessbitcoin_error != 0 ? "-22" : "couldnt load serialized tx or mismatched numinputs");
        free(V);
    } else jaddstr(retjson,"error",uselessbitcoin_error != 0 ? "-22" : "no rawtx or rawtx too big");
    return(jprint(retjson,1));
}

#include "../includes/iguana_apiundefs.h"

