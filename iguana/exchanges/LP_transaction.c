
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
//  LP_transaction.c
//  marketmaker
//


bits256 LP_broadcast(char *txname,char *symbol,char *txbytes)
{
    char *retstr; bits256 txid; int32_t i,sentflag = 0;
    memset(&txid,0,sizeof(txid));
    for (i=0; i<3; i++)
    {
        if ( (retstr= LP_sendrawtransaction(symbol,txbytes)) != 0 )
        {
            if ( is_hexstr(retstr,0) == 64 )
            {
                decode_hex(txid.bytes,32,retstr);
                sentflag = 1;
            }
            char str[65]; printf("[%s] %s RETSTR.(%s) %s.%s\n",txname,txbytes,retstr,symbol,bits256_str(str,txid));
            free(retstr);
        }
        if ( sentflag != 0 )
            break;
    }
    return(txid);
}

bits256 LP_broadcast_tx(char *name,char *symbol,uint8_t *data,int32_t datalen)
{
    bits256 txid; char *signedtx;
    memset(txid.bytes,0,sizeof(txid));
    if ( data != 0 && datalen != 0 )
    {
        char str[65];
#ifdef BASILISK_DISABLESENDTX
        txid = bits256_doublesha256(0,data,datalen);
        printf("%s <- dont sendrawtransaction (%s)\n",name,bits256_str(str,txid));
        return(txid);
#endif
        signedtx = malloc(datalen*2 + 1);
        init_hexbytes_noT(signedtx,data,datalen);
        txid = LP_broadcast(name,symbol,signedtx);
        // sent to nn_socket!
        free(signedtx);
    }
    return(txid);
}

uint64_t LP_txvalue(char *symbol,bits256 txid,int32_t vout)
{
    uint64_t value = 0; cJSON *txobj,*vouts,*utxoobj; int32_t numvouts;
    if ( (txobj= LP_gettx(symbol,txid)) != 0 )
    {
        if ( (vouts= jarray(&numvouts,txobj,"vout")) != 0 && vout < numvouts )
        {
            utxoobj = jitem(vouts,vout);
            if ( (value= jdouble(utxoobj,"amount")*SATOSHIDEN) == 0 && (value= jdouble(utxoobj,"value")*SATOSHIDEN) == 0 )
            {
                char str[65]; printf("%s LP_txvalue.%s strange utxo.(%s) vout.%d/%d\n",symbol,bits256_str(str,txid),jprint(utxoobj,0),vout,numvouts);
            }
        }
        free_json(txobj);
    }
    return(value);
}

int32_t LP_numconfirms(struct basilisk_swap *swap,struct basilisk_rawtx *rawtx)
{
    int32_t numconfirms = 100;
#ifndef BASILISK_DISABLEWAITTX
    cJSON *txobj;
    if ( (txobj= LP_gettx(symbol,txid)) != 0 )
    {
        numconfirms = jint(txobj,"confirmations");
        free_json(txobj);
    }
#endif
    return(numconfirms);
}


#ifdef later
int32_t iguana_msgtx_Vset(uint8_t *serialized,int32_t maxlen,struct iguana_msgtx *msgtx,struct vin_info *V)
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
            //printf("found multisig redeemscript\n");
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
    if ( (0) )
    {
        int32_t i; for (i=0; i<len; i++)
            printf("%02x",script[i]);
        printf(" <-script len.%d scriptlen.%d p2shlen.%d user.%d\n",len,scriptlen,p2shlen,userdatalen);
    }
    return(len);
}

int32_t bitcoin_verifyvins(uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,bits256 *signedtxidp,char **signedtx,struct iguana_msgtx *msgtx,uint8_t *serialized,int32_t maxlen,struct vin_info *V,uint32_t sighash,int32_t signtx,int32_t suppress_pubkeys)
{
    bits256 sigtxid; uint8_t *sig,*script; struct vin_info *vp; char vpnstr[64]; int32_t scriptlen,complete=0,j,vini=0,flag=0,siglen,numvouts,numsigs;
    numvouts = msgtx->tx_out;
    vpnstr[0] = 0;
    *signedtx = 0;
    memset(signedtxidp,0,sizeof(*signedtxidp));
    for (vini=0; vini<msgtx->tx_in; vini++)
    {
        if ( V->p2shscript[0] != 0 && V->p2shlen != 0 )
        {
            script = V->p2shscript;
            scriptlen = V->p2shlen;
            //printf("V->p2shlen.%d\n",V->p2shlen);
        }
        else
        {
            script = msgtx->vins[vini].spendscript;
            scriptlen = msgtx->vins[vini].spendlen;
        }
        sigtxid = bitcoin_sigtxid(pubtype,p2shtype,isPoS,height,serialized,maxlen,msgtx,vini,script,scriptlen,sighash,vpnstr,suppress_pubkeys);
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
                    siglen = bitcoin_sign(swap->ctx,sig,sigtxid,vp->signers[j].privkey,0);
                    //if ( (plen= bitcoin_pubkeylen(vp->signers[j].pubkey)) <= 0 )
                    bitcoin_pubkey33(swap->ctx,vp->signers[j].pubkey,vp->signers[j].privkey);
                    sig[siglen++] = sighash;
                    vp->signers[j].siglen = siglen;
                    /*char str[65]; printf("SIGTXID.(%s) ",bits256_str(str,sigtxid));
                     int32_t i; for (i=0; i<siglen; i++)
                     printf("%02x",sig[i]);
                     printf(" sig, ");
                     for (i=0; i<plen; i++)
                     printf("%02x",vp->signers[j].pubkey[i]);
                     // s2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1;
                     printf(" SIGNEDTX.[%02x] siglen.%d priv.%s\n",sig[siglen-1],siglen,bits256_str(str,vp->signers[j].privkey));*/
                }
                if ( sig == 0 || siglen == 0 )
                {
                    memset(vp->signers[j].pubkey,0,sizeof(vp->signers[j].pubkey));
                    continue;
                }
                if ( bitcoin_verify(sig,siglen-1,sigtxid,vp->signers[j].pubkey,bitcoin_pubkeylen(vp->signers[j].pubkey)) < 0 )
                {
                    int32_t k; for (k=0; k<bitcoin_pubkeylen(vp->signers[j].pubkey); k++)
                        printf("%02x",vp->signers[j].pubkey[k]);
                    printf(" SIG.%d.%d ERROR siglen.%d\n",vini,j,siglen);
                }
                else
                {
                    flag++;
                    numsigs++;
                    /*int32_t z;
                     for (z=0; z<siglen-1; z++)
                     printf("%02x",sig[z]);
                     printf(" <- sig[%d]\n",j);
                     for (z=0; z<33; z++)
                     printf("%02x",vp->signers[j].pubkey[z]);
                     printf(" <- pub, SIG.%d.%d VERIFIED numsigs.%d vs M.%d\n",vini,j,numsigs,vp->M);*/
                }
            }
            if ( numsigs >= vp->M )
                complete = 1;
        }
    }
    iguana_msgtx_Vset(serialized,maxlen,msgtx,V);
    cJSON *txobj = cJSON_CreateObject();
    *signedtx = iguana_rawtxbytes(pubtype,p2shtype,isPoS,height,txobj,msgtx,suppress_pubkeys);
    //printf("SIGNEDTX.(%s)\n",jprint(txobj,1));
    *signedtxidp = msgtx->txid;
    return(complete);
}

int32_t iguana_vininfo_create(uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msgtx,cJSON *vins,int32_t numinputs,struct vin_info *V)
{
    int32_t i,plen,finalized = 1,len = 0; struct vin_info *vp; //struct iguana_waccount *wacct; struct iguana_waddress *waddr; uint32_t sigsize,pubkeysize,p2shsize,userdatalen;
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
            len += iguana_parsevinobj(&serialized[len],maxsize,&msgtx->vins[i],jitem(vins,i),vp);
            if ( msgtx->vins[i].sequence < IGUANA_SEQUENCEID_FINAL )
                finalized = 0;
            if ( msgtx->vins[i].spendscript == 0 )
            {
                /*if ( iguana_RTunspentindfind(coin,&outpt,vp->coinaddr,vp->spendscript,&vp->spendlen,&vp->amount,&vp->height,msgtx->vins[i].prev_hash,msgtx->vins[i].prev_vout,coin->bundlescount-1,0) == 0 )
                 {
                 vp->unspentind = outpt.unspentind;
                 msgtx->vins[i].spendscript = vp->spendscript;
                 msgtx->vins[i].spendlen = vp->spendlen;
                 vp->hashtype = iguana_vinscriptparse(coin,vp,&sigsize,&pubkeysize,&p2shsize,&userdatalen,vp->spendscript,vp->spendlen);
                 vp->userdatalen = userdatalen;
                 printf("V %.8f (%s) spendscript.[%d] userdatalen.%d\n",dstr(vp->amount),vp->coinaddr,vp->spendlen,userdatalen);
                 }*/
            }
            else
            {
                memcpy(vp->spendscript,msgtx->vins[i].spendscript,msgtx->vins[i].spendlen);
                vp->spendlen = msgtx->vins[i].spendlen;
                _iguana_calcrmd160(pubtype,p2shtype,vp);
                if ( (plen= bitcoin_pubkeylen(vp->signers[0].pubkey)) > 0 )
                    bitcoin_address(vp->coinaddr,pubtype,vp->signers[0].pubkey,plen);
            }
            if ( vp->M == 0 && vp->N == 0 )
                vp->M = vp->N = 1;
            /*if ( vp->coinaddr[i] != 0 && (waddr= iguana_waddresssearch(&wacct,vp->coinaddr)) != 0 )
             {
             vp->signers[0].privkey = waddr->privkey;
             if ( (plen= bitcoin_pubkeylen(waddr->pubkey)) != vp->spendscript[1] || vp->spendscript[vp->spendlen-1] != 0xac )
             {
             if ( plen > 0 && plen < sizeof(vp->signers[0].pubkey) )
             memcpy(vp->signers[0].pubkey,waddr->pubkey,plen);
             }
             }*/
        }
    }
    return(finalized);
}

void iguana_ensure_privkey(struct iguana_info *coin,bits256 privkey)
{
    uint8_t pubkey33[33]; struct iguana_waccount *wacct; struct iguana_waddress *waddr,addr; char coinaddr[128];
    bitcoin_pubkey33(swap->ctx,pubkey33,privkey);
    bitcoin_address(coinaddr,coin->pubtype,pubkey33,33);
    //printf("privkey for (%s)\n",coinaddr);
    if ( myinfo->expiration != 0 && ((waddr= iguana_waddresssearch(&wacct,coinaddr)) == 0 || bits256_nonz(waddr->privkey) == 0) )
    {
        if ( waddr == 0 )
        {
            memset(&addr,0,sizeof(addr));
            iguana_waddresscalc(coin->pubtype,coin->wiftype,&addr,privkey);
            if ( (wacct= iguana_waccountfind("default")) != 0 )
                waddr = iguana_waddressadd(coin,wacct,&addr,0);
        }
        if ( waddr != 0 )
        {
            waddr->privkey = privkey;
            if ( bitcoin_priv2wif(waddr->wifstr,waddr->privkey,coin->wiftype) > 0 )
            {
                if ( (0) && waddr->wiftype != coin->wiftype )
                    printf("ensurepriv warning: mismatched wiftype %02x != %02x\n",waddr->wiftype,coin->wiftype);
                if ( (0) && waddr->addrtype != coin->pubtype )
                    printf("ensurepriv warning: mismatched addrtype %02x != %02x\n",waddr->addrtype,coin->pubtype);
            }
        }
    }
}

int32_t iguana_interpreter(struct iguana_info *coin,cJSON *logarray,int64_t nLockTime,struct vin_info *V,int32_t numvins)
{
    uint8_t script[IGUANA_MAXSCRIPTSIZE],*activescript,savescript[IGUANA_MAXSCRIPTSIZE]; char str[IGUANA_MAXSCRIPTSIZE*2+1]; int32_t vini,scriptlen,activescriptlen,savelen,errs = 0; cJSON *spendscript,*item=0;
    for (vini=0; vini<numvins; vini++)
    {
        savelen = V[vini].spendlen;
        memcpy(savescript,V[vini].spendscript,savelen);
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
        memcpy(V[vini].spendscript,activescript,activescriptlen);
        V[vini].spendlen = activescriptlen;
        spendscript = iguana_spendasm(coin,activescript,activescriptlen);
        if ( activescriptlen < 16 )
            continue;
        //printf("interpreter.(%s)\n",jprint(spendscript,0));
        if ( (scriptlen= bitcoin_assembler(coin,logarray,script,spendscript,1,nLockTime,&V[vini])) < 0 )
        {
            //printf("bitcoin_assembler error scriptlen.%d\n",scriptlen);
            errs++;
        }
        else if ( scriptlen != activescriptlen || memcmp(script,activescript,scriptlen) != 0 )
        {
            if ( logarray != 0 )
            {
                item = cJSON_CreateObject();
                jaddstr(item,"error","script reconstruction failed");
            }
            init_hexbytes_noT(str,activescript,activescriptlen);
            //printf("activescript.(%s)\n",str);
            if ( logarray != 0 && item != 0 )
                jaddstr(item,"original",str);
            init_hexbytes_noT(str,script,scriptlen);
            //printf("reconstructed.(%s)\n",str);
            if ( logarray != 0 )
            {
                jaddstr(item,"reconstructed",str);
                jaddi(logarray,item);
            } else printf(" scriptlen mismatch.%d vs %d or miscompare\n",scriptlen,activescriptlen);
            errs++;
        }
        memcpy(V[vini].spendscript,savescript,savelen);
        V[vini].spendlen = savelen;
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

bits256 iguana_str2priv(char *str)
{
    bits256 privkey; int32_t n; uint8_t addrtype; //struct iguana_waccount *wacct=0; struct iguana_waddress *waddr;
    memset(&privkey,0,sizeof(privkey));
    if ( str != 0 )
    {
        n = (int32_t)strlen(str) >> 1;
        if ( n == sizeof(bits256) && is_hexstr(str,sizeof(bits256)) > 0 )
            decode_hex(privkey.bytes,sizeof(privkey),str);
        else if ( bitcoin_wif2priv(&addrtype,&privkey,str) != sizeof(bits256) )
        {
            //if ( (waddr= iguana_waddresssearch(&wacct,str)) != 0 )
            //    privkey = waddr->privkey;
            //else memset(privkey.bytes,0,sizeof(privkey));
        }
    }
    return(privkey);
}

int32_t iguana_signrawtransaction(uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,struct iguana_msgtx *msgtx,char **signedtxp,bits256 *signedtxidp,struct vin_info *V,int32_t numinputs,char *rawtx,cJSON *vins,cJSON *privkeysjson)
{
    uint8_t *serialized,*serialized2,*serialized3,*serialized4,*extraspace,pubkeys[64][33]; int32_t finalized,i,len,n,z,plen,maxsize,complete = 0,extralen = 65536; char *privkeystr,*signedtx = 0; bits256 privkeys[64],privkey,txid; cJSON *item; cJSON *txobj = 0;
    maxsize = 1000000;
    memset(privkey.bytes,0,sizeof(privkey));
    if ( rawtx != 0 && rawtx[0] != 0 && (len= (int32_t)strlen(rawtx)>>1) < maxsize )
    {
        serialized = malloc(maxsize);
        serialized2 = malloc(maxsize);
        serialized3 = malloc(maxsize);
        serialized4 = malloc(maxsize);
        extraspace = malloc(extralen);
        memset(msgtx,0,sizeof(*msgtx));
        decode_hex(serialized,len,rawtx);
        // printf("call hex2json.(%s) vins.(%s)\n",rawtx,jprint(vins,0));
        if ( (txobj= bitcoin_hex2json(pubtype,p2shtype,isPoS,height,&txid,msgtx,rawtx,extraspace,extralen,serialized4,vins,V->suppress_pubkeys)) != 0 )
        {
            //printf("back from bitcoin_hex2json (%s)\n",jprint(vins,0));
        } else fprintf(stderr,"no txobj from bitcoin_hex2json\n");
        if ( (numinputs= cJSON_GetArraySize(vins)) > 0 )
        {
            //printf("numinputs.%d msgtx.%d\n",numinputs,msgtx->tx_in);
            memset(msgtx,0,sizeof(*msgtx));
            if ( iguana_rwmsgtx(pubtype,p2shtype,isPoS,height,0,0,serialized,maxsize,msgtx,&txid,"",extraspace,65536,vins,V->suppress_pubkeys) > 0 && numinputs == msgtx->tx_in )
            {
                memset(pubkeys,0,sizeof(pubkeys));
                memset(privkeys,0,sizeof(privkeys));
                if ( (n= cJSON_GetArraySize(privkeysjson)) > 0 )
                {
                    for (i=0; i<n; i++)
                    {
                        item = jitem(privkeysjson,i);
                        privkeystr = jstr(item,0);
                        if ( privkeystr == 0 || privkeystr[0] == 0 )
                            continue;
                        privkeys[i] = privkey = iguana_str2priv(privkeystr);
                        bitcoin_pubkey33(swap->ctx,pubkeys[i],privkey);
                        //if ( bits256_nonz(privkey) != 0 )
                        //    iguana_ensure_privkey(coin,privkey);
                    }
                }
                //printf("after privkeys tx_in.%d\n",msgtx->tx_in);
                for (i=0; i<msgtx->tx_in; i++)
                {
                    if ( msgtx->vins[i].p2shlen != 0 )
                    {
                        char coinaddr[64]; uint32_t userdatalen,sigsize,pubkeysize; uint8_t *userdata; int32_t j,k,hashtype,type,flag; struct vin_info mvin,mainvin; bits256 zero;
                        memset(zero.bytes,0,sizeof(zero));
                        coinaddr[0] = 0;
                        sigsize = 0;
                        flag = (msgtx->vins[i].vinscript[0] == 0);
                        type = bitcoin_scriptget(pubtype,p2shtype,&hashtype,&sigsize,&pubkeysize,&userdata,&userdatalen,&mainvin,msgtx->vins[i].vinscript+flag,msgtx->vins[i].scriptlen-flag,0);
                        //printf("i.%d flag.%d type.%d scriptlen.%d\n",i,flag,type,msgtx->vins[i].scriptlen);
                        if ( msgtx->vins[i].redeemscript != 0 )
                        {
                            //for (j=0; j<msgtx->vins[i].p2shlen; j++)
                            //    printf("%02x",msgtx->vins[i].redeemscript[j]);
                            bitcoin_address(coinaddr,p2shtype,msgtx->vins[i].redeemscript,msgtx->vins[i].p2shlen);
                            type = iguana_calcrmd160(pubtype,p2shtype,0,&mvin,msgtx->vins[i].redeemscript,msgtx->vins[i].p2shlen,zero,0,0);
                            for (j=0; j<mvin.N; j++)
                            {
                                if ( V->suppress_pubkeys == 0 )
                                {
                                    for (z=0; z<33; z++)
                                        V[i].signers[j].pubkey[z] = mvin.signers[j].pubkey[z];
                                }
                                if ( flag != 0 && pubkeysize == 33 && mainvin.signers[0].siglen != 0 ) // jl777: need to generalize
                                {
                                    if ( memcmp(mvin.signers[j].pubkey,mainvin.signers[0].pubkey,33) == 0 )
                                    {
                                        for (z=0; z<mainvin.signers[0].siglen; z++)
                                            V[i].signers[j].sig[z] = mainvin.signers[0].sig[z];
                                        V[i].signers[j].siglen = mainvin.signers[j].siglen;
                                        printf("[%d].signer[%d] <- from mainvin.[0]\n",i,j);
                                    }
                                }
                                for (k=0; k<n; k++)
                                {
                                    if ( V[i].signers[j].siglen == 0 && memcmp(mvin.signers[j].pubkey,pubkeys[k],33) == 0 )
                                    {
                                        V[i].signers[j].privkey = privkeys[k];
                                        if ( V->suppress_pubkeys == 0 )
                                        {
                                            for (z=0; z<33; z++)
                                                V[i].signers[j].pubkey[z] = pubkeys[k][z];
                                        }
                                        //printf("%s -> V[%d].signer.[%d] <- privkey.%d\n",mvin.signers[j].coinaddr,i,j,k);
                                        break;
                                    }
                                }
                            }
                            //printf("type.%d p2sh.[%d] -> %s M.%d N.%d\n",type,i,mvin.coinaddr,mvin.M,mvin.N);
                        }
                    }
                    if ( i < V->N )
                        V->signers[i].privkey = privkey;
                    if ( i < numinputs )
                        V[i].signers[0].privkey = privkey;
                    plen = bitcoin_pubkeylen(V->signers[i].pubkey);
                    if ( V->suppress_pubkeys == 0 && plen <= 0 )
                    {
                        if ( i < numinputs )
                        {
                            for (z=0; z<plen; z++)
                                V[i].signers[0].pubkey[z] = V->signers[i].pubkey[z];
                        }
                    }
                }
                finalized = iguana_vininfo_create(pubtype,p2shtype,isPoS,serialized2,maxsize,msgtx,vins,numinputs,V);
                //printf("finalized.%d\n",finalized);
                if ( (complete= bitcoin_verifyvins(pubtype,p2shtype,isPoS,height,signedtxidp,&signedtx,msgtx,serialized3,maxsize,V,SIGHASH_ALL,1,V->suppress_pubkeys)) > 0 && signedtx != 0 )
                {
                    /*int32_t tmp; //char str[65];
                     if ( (tmp= iguana_interpreter(coin,0,iguana_lockval(finalized,jint(txobj,"locktime")),V,numinputs)) < 0 )
                     {
                     printf("iguana_interpreter %d error.(%s)\n",tmp,signedtx);
                     complete = 0;
                     } */
                } else printf("complete.%d\n",complete);
            } else printf("rwmsgtx error\n");
        } else fprintf(stderr,"no inputs in vins.(%s)\n",vins!=0?jprint(vins,0):"null");
        free(extraspace);
        free(serialized), free(serialized2), free(serialized3), free(serialized4);
    } else return(-1);
    if ( txobj != 0 )
        free_json(txobj);
    *signedtxp = signedtx;
    return(complete);
}

int32_t basilisk_rawtx_return(struct basilisk_rawtx *rawtx,cJSON *item,int32_t lockinputs,struct vin_info *V)
{
    char *signedtx,*txbytes; cJSON *vins,*privkeyarray; int32_t i,n,retval = -1;
    if ( (txbytes= jstr(item,"rawtx")) != 0 && (vins= jobj(item,"vins")) != 0 )
    {
        privkeyarray = cJSON_CreateArray();
        jaddistr(privkeyarray,wifstr);
        if ( (signedtx= LP_signrawtx(rawtx->coin->symbol,&rawtx->I.signedtxid,&rawtx->I.completed,vins,txbytes,privkeyarray,V)) != 0 )
        {
            if ( lockinputs != 0 )
            {
                //printf("lockinputs\n");
                LP_unspentslock(rawtx->coin->symbol,vins);
                if ( (n= cJSON_GetArraySize(vins)) != 0 )
                {
                    bits256 txid; int32_t vout;
                    for (i=0; i<n; i++)
                    {
                        item = jitem(vins,i);
                        txid = jbits256(item,"txid");
                        vout = jint(item,"vout");
                    }
                }
            }
            rawtx->I.datalen = (int32_t)strlen(signedtx) >> 1;
            //rawtx->txbytes = calloc(1,rawtx->I.datalen);
            decode_hex(rawtx->txbytes,rawtx->I.datalen,signedtx);
            //printf("%s SIGNEDTX.(%s)\n",rawtx->name,signedtx);
            free(signedtx);
            retval = 0;
        } else printf("error signrawtx\n"); //do a very short timeout so it finishes via local poll
        free_json(privkeyarray);
    }
    return(retval);
}

cJSON *LP_createvins(struct basilisk_rawtx *dest,struct vin_info *V,struct basilisk_rawtx *rawtx,uint8_t *userdata,int32_t userdatalen,uint32_t sequenceid)
{
    cJSON *vins,*item,*sobj; char hexstr[8192];
    vins = cJSON_CreateArray();
    item = cJSON_CreateObject();
    if ( userdata != 0 && userdatalen > 0 )
    {
        memcpy(V[0].userdata,userdata,userdatalen);
        V[0].userdatalen = userdatalen;
        init_hexbytes_noT(hexstr,userdata,userdatalen);
        jaddstr(item,"userdata",hexstr);
#ifdef DISABLE_CHECKSIG
        needsig = 0;
#endif
    }
    //printf("rawtx B\n");
    if ( bits256_nonz(rawtx->I.actualtxid) != 0 )
        jaddbits256(item,"txid",rawtx->I.actualtxid);
    else jaddbits256(item,"txid",rawtx->I.signedtxid);
    jaddnum(item,"vout",0);
    sobj = cJSON_CreateObject();
    init_hexbytes_noT(hexstr,rawtx->spendscript,rawtx->I.spendlen);
    jaddstr(sobj,"hex",hexstr);
    jadd(item,"scriptPubKey",sobj);
    jaddnum(item,"suppress",dest->I.suppress_pubkeys);
    jaddnum(item,"sequence",sequenceid);
    if ( (dest->I.redeemlen= rawtx->I.redeemlen) != 0 )
    {
        init_hexbytes_noT(hexstr,rawtx->redeemscript,rawtx->I.redeemlen);
        memcpy(dest->redeemscript,rawtx->redeemscript,rawtx->I.redeemlen);
        jaddstr(item,"redeemScript",hexstr);
    }
    jaddi(vins,item);
    return(vins);
}

int32_t _basilisk_rawtx_gen(char *str,uint32_t swapstarted,uint8_t *pubkey33,int32_t iambob,int32_t lockinputs,struct basilisk_rawtx *rawtx,uint32_t locktime,uint8_t *script,int32_t scriptlen,int64_t txfee,int32_t minconf,int32_t delay,bits256 privkey)
{
    char scriptstr[1024],wifstr[256],coinaddr[64],*signedtx,*rawtxbytes; uint32_t basilisktag; int32_t retval = -1; cJSON *vins,*privkeys,*addresses,*valsobj; struct vin_info *V;
    //bitcoin_address(coinaddr,rawtx->coin->chain->pubtype,myinfo->persistent_pubkey33,33);
    if ( rawtx->coin->changeaddr[0] == 0 )
    {
        bitcoin_address(rawtx->coin->changeaddr,rawtx->coin->pubtype,pubkey33,33);
        printf("set change address.(%s)\n",rawtx->coin->changeaddr);
    }
    init_hexbytes_noT(scriptstr,script,scriptlen);
    basilisktag = (uint32_t)rand();
    valsobj = cJSON_CreateObject();
    jaddstr(valsobj,"coin",rawtx->coin->symbol);
    jaddstr(valsobj,"spendscript",scriptstr);
    jaddstr(valsobj,"changeaddr",rawtx->coin->changeaddr);
    jadd64bits(valsobj,"satoshis",rawtx->I.amount);
    if ( strcmp(rawtx->coin->symbol,"BTC") == 0 && txfee > 0 && txfee < 50000 )
        txfee = 50000;
    jadd64bits(valsobj,"txfee",txfee);
    jaddnum(valsobj,"minconf",minconf);
    if ( locktime == 0 )
        locktime = (uint32_t)time(NULL) - 777;
    jaddnum(valsobj,"locktime",locktime);
    jaddnum(valsobj,"timeout",30000);
    jaddnum(valsobj,"timestamp",swapstarted+delay);
    addresses = cJSON_CreateArray();
    bitcoin_address(coinaddr,rawtx->coin->pubtype,pubkey33,33);
    jaddistr(addresses,coinaddr);
    jadd(valsobj,"addresses",addresses);
    rawtx->I.locktime = locktime;
    printf("%s locktime.%u\n",rawtx->name,locktime);
    V = calloc(256,sizeof(*V));
    privkeys = cJSON_CreateArray();
    bitcoin_priv2wif(wifstr,privkey,rawtx->coin->wiftype);
    jaddistr(privkeys,wifstr);
    vins = LP_createvins(rawtx,V,rawtx,0,0,0xffffffff);
    rawtx->vins = jduplicate(vins);
    jdelete(valsobj,"vin");
    jadd(valsobj,"vin",vins);
    if ( (rawtxbytes= bitcoin_json2hex(rawtx->coin->isPoS,&rawtx->I.txid,valsobj,V)) != 0 )
    {
        //printf("rawtx.(%s) vins.%p\n",rawtxbytes,vins);
        if ( (signedtx= LP_signrawtx(rawtx->coin->symbol,&rawtx->I.signedtxid,&rawtx->I.completed,vins,rawtxbytes,privkeys,V)) != 0 )
        {
            rawtx->I.datalen = (int32_t)strlen(signedtx) >> 1;
            if ( rawtx->I.datalen <= sizeof(rawtx->txbytes) )
                decode_hex(rawtx->txbytes,rawtx->I.datalen,signedtx);
            else printf("DEX tx is too big %d vs %d\n",rawtx->I.datalen,(int32_t)sizeof(rawtx->txbytes));
            if ( signedtx != rawtxbytes )
                free(signedtx);
            if ( rawtx->I.completed != 0 )
                retval = 0;
            else printf("couldnt complete sign transaction %s\n",rawtx->name);
        } else printf("error signing\n");
        free(rawtxbytes);
    } else printf("error making rawtx\n");
    free_json(privkeys);
    free_json(valsobj);
    free(V);
    return(retval);
}


int32_t _basilisk_rawtx_sign(char *symbol,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,uint8_t wiftype,struct basilisk_swap *swap,uint32_t timestamp,uint32_t locktime,uint32_t sequenceid,struct basilisk_rawtx *dest,struct basilisk_rawtx *rawtx,bits256 privkey,bits256 *privkey2,uint8_t *userdata,int32_t userdatalen,int32_t ignore_cltverr)
{
    char *rawtxbytes=0,*signedtx=0,wifstr[128]; cJSON *txobj,*vins,*privkeys; int32_t needsig=1,retval = -1; struct vin_info *V;
    V = calloc(256,sizeof(*V));
    V[0].signers[0].privkey = privkey;
    bitcoin_pubkey33(swap->ctx,V[0].signers[0].pubkey,privkey);
    privkeys = cJSON_CreateArray();
    bitcoin_priv2wif(wifstr,privkey,wiftype);
    jaddistr(privkeys,wifstr);
    if ( privkey2 != 0 )
    {
        V[0].signers[1].privkey = *privkey2;
        bitcoin_pubkey33(swap->ctx,V[0].signers[1].pubkey,*privkey2);
        bitcoin_priv2wif(wifstr,*privkey2,wiftype);
        jaddistr(privkeys,wifstr);
        V[0].N = V[0].M = 2;
        //char str[65]; printf("add second privkey.(%s) %s\n",jprint(privkeys,0),bits256_str(str,*privkey2));
    } else V[0].N = V[0].M = 1;
    V[0].suppress_pubkeys = dest->I.suppress_pubkeys;
    V[0].ignore_cltverr = ignore_cltverr;
    if ( dest->I.redeemlen != 0 )
        memcpy(V[0].p2shscript,dest->redeemscript,dest->I.redeemlen), V[0].p2shlen = dest->I.redeemlen;
    txobj = bitcoin_txcreate(symbol,isPoS,locktime,userdata == 0 ? 1 : 1,timestamp);//rawtx->coin->locktime_txversion);
    vins = LP_createvins(dest,V,rawtx,userdata,userdatalen,sequenceid);
    jdelete(txobj,"vin");
    jadd(txobj,"vin",vins);
    //printf("basilisk_rawtx_sign locktime.%u/%u for %s spendscript.%s -> %s, suppress.%d\n",rawtx->I.locktime,dest->I.locktime,rawtx->name,hexstr,dest->name,dest->I.suppress_pubkeys);
    txobj = bitcoin_txoutput(txobj,dest->spendscript,dest->I.spendlen,dest->I.amount);
    if ( (rawtxbytes= bitcoin_json2hex(isPoS,&dest->I.txid,txobj,V)) != 0 )
    {
        //printf("rawtx.(%s) vins.%p\n",rawtxbytes,vins);
        if ( needsig == 0 )
            signedtx = rawtxbytes;
        if ( signedtx != 0 || (signedtx= LP_signrawtx(symbol,&dest->I.signedtxid,&dest->I.completed,vins,rawtxbytes,privkeys,V)) != 0 )
        {
            dest->I.datalen = (int32_t)strlen(signedtx) >> 1;
            if ( dest->I.datalen <= sizeof(dest->txbytes) )
                decode_hex(dest->txbytes,dest->I.datalen,signedtx);
            else printf("DEX tx is too big %d vs %d\n",dest->I.datalen,(int32_t)sizeof(dest->txbytes));
            if ( signedtx != rawtxbytes )
                free(signedtx);
            if ( dest->I.completed != 0 )
                retval = 0;
            else printf("couldnt complete sign transaction %s\n",rawtx->name);
        } else printf("error signing\n");
        free(rawtxbytes);
    } else printf("error making rawtx\n");
    free_json(privkeys);
    free_json(txobj);
    free(V);
    return(retval);
}
#endif

char *basilisk_swap_bobtxspend(bits256 *signedtxidp,uint64_t txfee,char *name,char *symbol,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,uint8_t wiftype,void *ctx,bits256 privkey,bits256 *privkey2p,uint8_t *redeemscript,int32_t redeemlen,uint8_t *userdata,int32_t userdatalen,bits256 utxotxid,int32_t vout,uint8_t *pubkey33,int32_t finalseqid,uint32_t expiration,int64_t *destamountp)
{
    char *rawtxbytes=0,*signedtx=0,str[65],hexstr[999],wifstr[128],destaddr[64]; uint8_t spendscript[512],addrtype,rmd160[20]; cJSON *utxoobj,*txobj,*vins,*item,*sobj,*privkeys; int32_t completed,spendlen,ignore_cltverr=1,suppress_pubkeys=1; struct vin_info *V; uint32_t timestamp,locktime = 0,sequenceid = 0xffffffff * finalseqid; bits256 txid; uint64_t destamount;
    *destamountp = 0;
    memset(signedtxidp,0,sizeof(*signedtxidp));
    if ( finalseqid == 0 )
        locktime = expiration;
    //printf("bobtxspend.%s redeem.[%d]\n",symbol,redeemlen);
    if ( redeemlen < 0 )
        return(0);
    if ( (utxoobj= LP_gettxout(symbol,utxotxid,vout)) == 0 )
    {
        printf("basilisk_swap_bobtxspend.%s utxo already spent or doesnt exist\n",name);
        return(0);
    }
    if ( (destamount= jdouble(utxoobj,"amount")*SATOSHIDEN) == 0 && (destamount= jdouble(utxoobj,"value")*SATOSHIDEN) == 0 )
    {
        printf("%s %s basilisk_swap_bobtxspend.%s strange utxo.(%s)\n",symbol,bits256_str(str,utxotxid),name,jprint(utxoobj,0));
        free_json(utxoobj);
        return(0);
    } else free_json(utxoobj);
    *destamountp = destamount;
    if ( destamount > txfee )
        destamount -= txfee;
    timestamp = (uint32_t)time(NULL);
    V = calloc(256,sizeof(*V));
    privkeys = cJSON_CreateArray();
    if ( privkey2p != 0 )
    {
        V[0].signers[1].privkey = *privkey2p;
        bitcoin_pubkey33(ctx,V[0].signers[1].pubkey,*privkey2p);
        bitcoin_priv2wif(wifstr,*privkey2p,wiftype);
        jaddistr(privkeys,wifstr);
        V[0].N = V[0].M = 2;
    } else V[0].N = V[0].M = 1;
    V[0].signers[0].privkey = privkey;
    bitcoin_pubkey33(ctx,V[0].signers[0].pubkey,privkey);
    bitcoin_priv2wif(wifstr,privkey,wiftype);
    jaddistr(privkeys,wifstr);
    V[0].suppress_pubkeys = suppress_pubkeys;
    V[0].ignore_cltverr = ignore_cltverr;
    if ( redeemlen != 0 )
        memcpy(V[0].p2shscript,redeemscript,redeemlen), V[0].p2shlen = redeemlen;
    txobj = bitcoin_txcreate(symbol,isPoS,locktime,1,timestamp);
    vins = cJSON_CreateArray();
    item = cJSON_CreateObject();
    if ( userdata != 0 && userdatalen > 0 )
    {
        memcpy(V[0].userdata,userdata,userdatalen);
        V[0].userdatalen = userdatalen;
        init_hexbytes_noT(hexstr,userdata,userdatalen);
        jaddstr(item,"userdata",hexstr);
    }
    jaddbits256(item,"txid",utxotxid);
    jaddnum(item,"vout",vout);
    sobj = cJSON_CreateObject();
    bitcoin_address(destaddr,pubtype,pubkey33,33);
    bitcoin_addr2rmd160(&addrtype,rmd160,destaddr);
    /*int32_t i;
     for (i=0; i<33; i++)
     printf("%02x",pubkey33[i]);
     printf(" pubkey33 ->\n");
     for (i=0; i<20; i++)
     printf("%02x",rmd160[i]);
     printf(" destaddr.(%s)\n",destaddr);
     calc_rmd160_sha256(rmd160,pubkey33,33);
     for (i=0; i<20; i++)
     printf("%02x",rmd160[i]);
     printf(" <- vs direct calc\n");*/
    spendlen = bitcoin_standardspend(spendscript,0,rmd160);
    init_hexbytes_noT(hexstr,spendscript,spendlen);
    jaddstr(sobj,"hex",hexstr);
    jadd(item,"scriptPubKey",sobj);
    jaddnum(item,"suppress",suppress_pubkeys);
    jaddnum(item,"sequence",sequenceid);
    if ( redeemlen != 0 )
    {
        init_hexbytes_noT(hexstr,redeemscript,redeemlen);
        jaddstr(item,"redeemScript",hexstr);
    }
    jaddi(vins,item);
    jdelete(txobj,"vin");
    jadd(txobj,"vin",vins);
    txobj = bitcoin_txoutput(txobj,spendscript,spendlen,destamount);
    if ( (rawtxbytes= bitcoin_json2hex(isPoS,&txid,txobj,V)) != 0 )
    {
        //printf("locktime.%u sequenceid.%x rawtx.(%s) vins.(%s)\n",locktime,sequenceid,rawtxbytes,jprint(vins,0));
        if ( (signedtx= LP_signrawtx(symbol,signedtxidp,&completed,vins,rawtxbytes,privkeys,V)) == 0 )
            printf("couldnt sign transaction\n");
        else if ( completed == 0 )
        {
            printf("incomplete signing\n");
            if ( signedtx != 0 )
                free(signedtx), signedtx = 0;
        } else printf("%s -> %s\n",name,bits256_str(str,*signedtxidp));
        free(rawtxbytes);
    } else printf("error making rawtx\n");
    free_json(privkeys);
    free_json(txobj);
    free(V);
    return(signedtx);
}

int32_t basilisk_rawtx_gen(void *ctx,char *str,uint32_t swapstarted,uint8_t *pubkey33,int32_t iambob,int32_t lockinputs,struct basilisk_rawtx *rawtx,uint32_t locktime,uint8_t *script,int32_t scriptlen,int64_t txfee,int32_t minconf,int32_t delay,bits256 privkey)
{
    int32_t retval=-1,len,iter; char *signedtx; struct iguana_info *coin; int64_t newtxfee=0,destamount;
    if ( (coin= rawtx->coin) == 0 )
        return(-1);
    //return(_basilisk_rawtx_gen(str,swapstarted,pubkey33,iambob,lockinputs,rawtx,locktime,script,scriptlen,txfee,minconf,delay,privkey));
    for (iter=0; iter<2; iter++)
    {
        if ( (signedtx= basilisk_swap_bobtxspend(&rawtx->I.signedtxid,iter == 0 ? txfee : newtxfee,str,coin->symbol,coin->pubtype,coin->p2shtype,coin->isPoS,coin->wiftype,ctx,privkey,0,0,0,0,0,rawtx->utxotxid,rawtx->utxovout,pubkey33,1,0,&destamount)) != 0 )
        {
            rawtx->I.datalen = (int32_t)strlen(signedtx) >> 1;
            if ( rawtx->I.datalen <= sizeof(rawtx->txbytes) )
            {
                decode_hex(rawtx->txbytes,rawtx->I.datalen,signedtx);
                rawtx->I.completed = 1;
                retval = 0;
            }
            free(signedtx);
            if ( strcmp(coin->symbol,"BTC") != 0 )
                return(retval);
            len = rawtx->I.datalen;
            if ( coin->estimatedrate == 0 )
                coin->estimatedrate = LP_getestimatedrate(coin->symbol);
            newtxfee = coin->estimatedrate * len;
            printf("txfee %.8f -> newtxfee %.8f\n",dstr(txfee),dstr(newtxfee));
        } else break;
    }
    return(retval);
}

int32_t basilisk_rawtx_sign(char *symbol,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,uint8_t wiftype,struct basilisk_swap *swap,struct basilisk_rawtx *dest,struct basilisk_rawtx *rawtx,bits256 privkey,bits256 *privkey2,uint8_t *userdata,int32_t userdatalen,int32_t ignore_cltverr)
{
    char *signedtx; int64_t txfee,newtxfee=0,estimatedrate,destamount; uint32_t timestamp,locktime=0,sequenceid = 0xffffffff; int32_t iter,len,retval = -1;
    timestamp = swap->I.started;
    if ( dest == &swap->aliceclaim )
        locktime = swap->bobdeposit.I.locktime + 1, sequenceid = 0;
    else if ( dest == &swap->bobreclaim )
        locktime = swap->bobpayment.I.locktime + 1, sequenceid = 0;
    txfee = strcmp("BTC",symbol) == 0 ? 0 : 10000;
    for (iter=0; iter<2; iter++)
    {
        if ( (signedtx= basilisk_swap_bobtxspend(&rawtx->I.signedtxid,iter == 0 ? txfee : newtxfee,rawtx->name,symbol,pubtype,p2shtype,isPoS,wiftype,swap->ctx,privkey,privkey2,0,0,userdata,userdatalen,rawtx->utxotxid,rawtx->utxovout,rawtx->pubkey33,1,0,&destamount)) != 0 )
        {
            rawtx->I.datalen = (int32_t)strlen(signedtx) >> 1;
            if ( rawtx->I.datalen <= sizeof(rawtx->txbytes) )
            {
                decode_hex(rawtx->txbytes,rawtx->I.datalen,signedtx);
                rawtx->I.completed = 1;
                retval = 0;
            }
            free(signedtx);
            if ( strcmp(symbol,"BTC") != 0 )
                return(retval);
            len = rawtx->I.datalen;
            estimatedrate = LP_getestimatedrate(symbol);
            newtxfee = estimatedrate * len;
        } else break;
    }
    return(retval);
    //return(_basilisk_rawtx_sign(symbol,pubtype,p2shtype,isPoS,wiftype,swap,timestamp,locktime,sequenceid,dest,rawtx,privkey,privkey2,userdata,userdatalen,ignore_cltverr));
}

int32_t basilisk_alicescript(uint8_t *redeemscript,int32_t *redeemlenp,uint8_t *script,int32_t n,char *msigaddr,uint8_t altps2h,bits256 pubAm,bits256 pubBn)
{
    uint8_t p2sh160[20]; struct vin_info V;
    memset(&V,0,sizeof(V));
    memcpy(&V.signers[0].pubkey[1],pubAm.bytes,sizeof(pubAm)), V.signers[0].pubkey[0] = 0x02;
    memcpy(&V.signers[1].pubkey[1],pubBn.bytes,sizeof(pubBn)), V.signers[1].pubkey[0] = 0x03;
    V.M = V.N = 2;
    *redeemlenp = bitcoin_MofNspendscript(p2sh160,redeemscript,n,&V);
    bitcoin_address(msigaddr,altps2h,p2sh160,sizeof(p2sh160));
    n = bitcoin_p2shspend(script,0,p2sh160);
    //for (i=0; i<*redeemlenp; i++)
    //    printf("%02x",redeemscript[i]);
    //printf(" <- redeemscript alicetx\n");
    return(n);
}

char *basilisk_swap_Aspend(char *name,char *symbol,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,uint8_t wiftype,void *ctx,bits256 privAm,bits256 privBn,bits256 utxotxid,int32_t vout,uint8_t pubkey33[33],uint32_t expiration,int64_t *destamountp)
{
    char msigaddr[64],*signedtx = 0; int32_t spendlen,redeemlen; uint8_t tmp33[33],redeemscript[512],spendscript[128]; bits256 pubAm,pubBn,signedtxid; uint64_t txfee;
    if ( bits256_nonz(privAm) != 0 && bits256_nonz(privBn) != 0 )
    {
        pubAm = bitcoin_pubkey33(ctx,tmp33,privAm);
        pubBn = bitcoin_pubkey33(ctx,tmp33,privBn);
        //char str[65];
        //printf("pubAm.(%s)\n",bits256_str(str,pubAm));
        //printf("pubBn.(%s)\n",bits256_str(str,pubBn));
        spendlen = basilisk_alicescript(redeemscript,&redeemlen,spendscript,0,msigaddr,p2shtype,pubAm,pubBn);
        //char str[65]; printf("%s utxo.(%s) redeemlen.%d spendlen.%d\n",msigaddr,bits256_str(str,utxotxid),redeemlen,spendlen);
        /*rev = privAm;
         for (i=0; i<32; i++)
         privAm.bytes[i] = rev.bytes[31 - i];
         rev = privBn;
         for (i=0; i<32; i++)
         privBn.bytes[i] = rev.bytes[31 - i];*/
        txfee = LP_txfee(symbol);
        signedtx = basilisk_swap_bobtxspend(&signedtxid,txfee,name,symbol,pubtype,p2shtype,isPoS,wiftype,ctx,privAm,&privBn,redeemscript,redeemlen,0,0,utxotxid,vout,pubkey33,1,expiration,destamountp);
    }
    return(signedtx);
}

int32_t LP_swap_txdestaddr(char *destaddr,bits256 txid,int32_t vout,cJSON *txobj)
{
    int32_t n,m,retval = -1; cJSON *vouts,*item,*addresses,*skey; char *addr;
    if ( (vouts= jarray(&n,txobj,"vout")) != 0 && vout < n )
    {
        item = jitem(vouts,vout);
        if ( (skey= jobj(item,"scriptPubKey")) != 0 && (addresses= jarray(&m,skey,"addresses")) != 0 )
        {
            item = jitem(addresses,0);
            if ( (addr= jstr(item,0)) != 0 )
            {
                safecopy(destaddr,addr,64);
                retval = 0;
            }
            //printf("item.(%s) -> dest.(%s)\n",jprint(item,0),destaddr);
        }
    }
    return(retval);
}

int32_t LP_swap_getcoinaddr(char *symbol,char *coinaddr,bits256 txid,int32_t vout)
{
    cJSON *retjson;
    coinaddr[0] = 0;
    if ( (retjson= LP_gettx(symbol,txid)) != 0 )
    {
        LP_swap_txdestaddr(coinaddr,txid,vout,retjson);
        free_json(retjson);
    }
    return(coinaddr[0] != 0);
}

int32_t basilisk_swap_getsigscript(char *symbol,uint8_t *script,int32_t maxlen,bits256 txid,int32_t vini)
{
    cJSON *retjson,*vins,*item,*skey; int32_t n,scriptlen = 0; char *hexstr;
    if ( (retjson= LP_gettx(symbol,txid)) != 0 )
    {
        if ( (vins= jarray(&n,retjson,"vin")) != 0 && vini < n )
        {
            item = jitem(vins,vini);
            if ( (skey= jobj(item,"scriptSig")) != 0 && (hexstr= jstr(skey,"hex")) != 0 && (scriptlen= (int32_t)strlen(hexstr)) < maxlen*2 )
            {
                scriptlen >>= 1;
                decode_hex(script,scriptlen,hexstr);
                //char str[65]; printf("%s/v%d sigscript.(%s)\n",bits256_str(str,txid),vini,hexstr);
            }
        }
        free_json(retjson);
    }
    return(scriptlen);
}

int64_t basilisk_txvalue(char *symbol,bits256 txid,int32_t vout)
{
    cJSON *txobj,*vouts,*item; int32_t n; int64_t value = 0;
    //char str[65]; printf("%s txvalue.(%s)\n",symbol,bits256_str(str,txid));
    if ( (txobj= LP_gettx(symbol,txid)) != 0 )
    {
        //printf("txobj.(%s)\n",jprint(txobj,0));
        if ( (vouts= jarray(&n,txobj,"vout")) != 0 )
        {
            item = jitem(vouts,vout);
            if ( (value= jdouble(item,"amount") * SATOSHIDEN) == 0 )
                value = jdouble(item,"value") * SATOSHIDEN;
        }
        free_json(txobj);
    }
    return(value);
}

bits256 _LP_swap_spendtxid(char *symbol,char *destaddr,char *coinaddr,bits256 utxotxid,int32_t vout)
{
    char *retstr,*addr; cJSON *array,*item,*array2; int32_t i,n,m; bits256 spendtxid,txid;
    memset(&spendtxid,0,sizeof(spendtxid));
    if ( (retstr= blocktrail_listtransactions(symbol,coinaddr,100,0)) != 0 )
    {
        if ( (array= cJSON_Parse(retstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (item= jitem(array,i)) == 0 )
                        continue;
                    txid = jbits256(item,"txid");
                    if ( bits256_nonz(txid) == 0 )
                    {
                        if ( (array2= jarray(&m,item,"inputs")) != 0 && m == 1 )
                        {
                            //printf("found inputs with %s\n",bits256_str(str,spendtxid));
                            txid = jbits256(jitem(array2,0),"output_hash");
                            if ( bits256_cmp(txid,utxotxid) == 0 )
                            {
                                //printf("matched %s\n",bits256_str(str,txid));
                                if ( (array2= jarray(&m,item,"outputs")) != 0 && m == 1 && (addr= jstr(jitem(array2,0),"address")) != 0 )
                                {
                                    spendtxid = jbits256(item,"hash");
                                    strcpy(destaddr,addr);
                                    //printf("set spend addr.(%s) <- %s\n",addr,jprint(item,0));
                                    break;
                                }
                            }
                        }
                    }
                    else if ( bits256_cmp(txid,utxotxid) == 0 )
                    {
                        spendtxid = jbits256(item,"spendtxid");
                        if ( bits256_nonz(spendtxid) != 0 )
                        {
                            LP_swap_getcoinaddr(symbol,destaddr,spendtxid,0);
                            //char str[65]; printf("found spendtxid.(%s) -> %s\n",bits256_str(str,spendtxid),destaddr);
                            break;
                        }
                    }
                }
            }
            free_json(array);
        }
        free(retstr);
    }
    return(spendtxid);
}

bits256 LP_swap_spendtxid(char *symbol,char *destaddr,bits256 utxotxid,int32_t vout)
{
    bits256 spendtxid,txid; char *catstr,*addr; cJSON *array,*item,*item2,*txobj,*vins; int32_t i,n,m; char coinaddr[64],str[65];
    // listtransactions or listspents
    destaddr[0] = 0;
    coinaddr[0] = 0;
    memset(&spendtxid,0,sizeof(spendtxid));
    //char str[65]; printf("swap %s spendtxid.(%s)\n",symbol,bits256_str(str,utxotxid));
    if ( 0 && strcmp("BTC",symbol) == 0 )
    {
        //[{"type":"sent","confirmations":379,"height":275311,"timestamp":1492084664,"txid":"8703c5517bc57db38134058370a14e99b8e662b99ccefa2061dea311bbd02b8b","vout":0,"amount":117.50945263,"spendtxid":"cf2509e076fbb9b22514923df916b7aacb1391dce9c7e1460b74947077b12510","vin":0,"paid":{"type":"paid","txid":"cf2509e076fbb9b22514923df916b7aacb1391dce9c7e1460b74947077b12510","height":275663,"timestamp":1492106024,"vouts":[{"RUDpN6PEBsE7ZFbGjUxk1W3QVsxnjBLYw6":117.50935263}]}}]
        LP_swap_getcoinaddr(symbol,coinaddr,utxotxid,vout);
        if ( coinaddr[0] != 0 )
            spendtxid = _LP_swap_spendtxid(symbol,destaddr,coinaddr,utxotxid,vout);
    }
    else
    {
        if ( (array= LP_listtransactions(symbol,destaddr,1000,0)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (item= jitem(array,i)) == 0 )
                        continue;
                    txid = jbits256(item,"txid");
                    if ( vout == juint(item,"vout") && bits256_cmp(txid,utxotxid) == 0 && (addr= jstr(item,"address")) != 0 )
                    {
                        if ( (catstr= jstr(item,"category")) != 0 )
                        {
                            if (strcmp(catstr,"send") == 0 )
                            {
                                strncpy(destaddr,addr,63);
                                //printf("(%s) <- (%s) item.%d.[%s]\n",destaddr,coinaddr,i,jprint(item,0));
                                if ( coinaddr[0] != 0 )
                                    break;
                            }
                            if (strcmp(catstr,"receive") == 0 )
                            {
                                strncpy(coinaddr,addr,63);
                                //printf("receive dest.(%s) <- (%s)\n",destaddr,coinaddr);
                                if ( destaddr[0] != 0 )
                                    break;
                            }
                        }
                    }
                }
            }
            free_json(array);
        }
        if ( destaddr[0] != 0 )
        {
            if ( (array= LP_listtransactions(symbol,destaddr,1000,0)) != 0 )
            {
                if ( (n= cJSON_GetArraySize(array)) > 0 )
                {
                    for (i=0; i<n; i++)
                    {
                        if ( (item= jitem(array,i)) == 0 )
                            continue;
                        if ( (catstr= jstr(item,"category")) != 0 && strcmp(catstr,"send") == 0 )
                        {
                            txid = jbits256(item,"txid");
                            if ( (txobj= LP_gettx(symbol,txid)) != 0 )
                            {
                                if ( (vins= jarray(&m,txobj,"vin")) != 0 && m > jint(item,"vout") )
                                {
                                    item2 = jitem(vins,jint(item,"vout"));
                                    if ( bits256_cmp(utxotxid,jbits256(item2,"txid")) == 0 && vout == jint(item2,"vout") )
                                    {
                                        spendtxid = txid;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if ( i == n )
                        printf("dpowlist: native couldnt find spendtxid for %s\n",bits256_str(str,utxotxid));
                }
                free_json(array);
            }
            if ( bits256_nonz(spendtxid) != 0 )
                return(spendtxid);
        }
        /*if ( iguana_isnotarychain(symbol) >= 0 )
        {
            LP_swap_getcoinaddr(symbol,coinaddr,utxotxid,vout);
            printf("fallback use DEX for native (%s) (%s)\n",coinaddr,bits256_str(str,utxotxid));
            if ( coinaddr[0] != 0 )
            {
                spendtxid = _LP_swap_spendtxid(symbol,destaddr,coinaddr,utxotxid,vout);
                printf("spendtxid.(%s)\n",bits256_str(str,spendtxid));
            }
        }*/
    }
    return(spendtxid);
}

int32_t basilisk_swap_bobredeemscript(int32_t depositflag,int32_t *secretstartp,uint8_t *redeemscript,uint32_t locktime,bits256 pubA0,bits256 pubB0,bits256 pubB1,bits256 privAm,bits256 privBn,uint8_t *secretAm,uint8_t *secretAm256,uint8_t *secretBn,uint8_t *secretBn256)
{
    int32_t i,n=0; bits256 cltvpub,destpub,privkey; uint8_t pubkeyA[33],pubkeyB[33],secret160[20],secret256[32];
    if ( depositflag != 0 )
    {
        pubkeyA[0] = 0x02, cltvpub = pubA0;
        pubkeyB[0] = 0x03, destpub = pubB0;
        privkey = privBn;
        memcpy(secret160,secretBn,20);
        memcpy(secret256,secretBn256,32);
    }
    else
    {
        pubkeyA[0] = 0x03, cltvpub = pubB1;
        pubkeyB[0] = 0x02, destpub = pubA0;
        privkey = privAm;
        memcpy(secret160,secretAm,20);
        memcpy(secret256,secretAm256,32);
    }
    //for (i=0; i<32; i++)
    //    printf("%02x",secret256[i]);
    //printf(" <- secret256 depositflag.%d nonz.%d\n",depositflag,bits256_nonz(privkey));
    if ( bits256_nonz(cltvpub) == 0 || bits256_nonz(destpub) == 0 )
        return(-1);
    for (i=0; i<20; i++)
        if ( secret160[i] != 0 )
            break;
    if ( i == 20 )
        return(-1);
    memcpy(pubkeyA+1,cltvpub.bytes,sizeof(cltvpub));
    memcpy(pubkeyB+1,destpub.bytes,sizeof(destpub));
    redeemscript[n++] = SCRIPT_OP_IF;
    n = bitcoin_checklocktimeverify(redeemscript,n,locktime);
#ifdef DISABLE_CHECKSIG
    n = bitcoin_secret256spend(redeemscript,n,cltvpub);
#else
    n = bitcoin_pubkeyspend(redeemscript,n,pubkeyA);
#endif
    redeemscript[n++] = SCRIPT_OP_ELSE;
    if ( secretstartp != 0 )
        *secretstartp = n + 2;
    if ( 1 )
    {
        if ( 1 && bits256_nonz(privkey) != 0 )
        {
            uint8_t bufA[20],bufB[20];
            revcalc_rmd160_sha256(bufA,privkey);
            calc_rmd160_sha256(bufB,privkey.bytes,sizeof(privkey));
            /*if ( memcmp(bufA,secret160,sizeof(bufA)) == 0 )
             printf("MATCHES BUFA\n");
             else if ( memcmp(bufB,secret160,sizeof(bufB)) == 0 )
             printf("MATCHES BUFB\n");
             else printf("secret160 matches neither\n");
             for (i=0; i<20; i++)
             printf("%02x",bufA[i]);
             printf(" <- revcalc\n");
             for (i=0; i<20; i++)
             printf("%02x",bufB[i]);
             printf(" <- calc\n");*/
            memcpy(secret160,bufB,20);
        }
        n = bitcoin_secret160verify(redeemscript,n,secret160);
    }
    else
    {
        redeemscript[n++] = 0xa8;//IGUANA_OP_SHA256;
        redeemscript[n++] = 0x20;
        memcpy(&redeemscript[n],secret256,0x20), n += 0x20;
        redeemscript[n++] = 0x88; //SCRIPT_OP_EQUALVERIFY;
    }
#ifdef DISABLE_CHECKSIG
    n = bitcoin_secret256spend(redeemscript,n,destpub);
#else
    n = bitcoin_pubkeyspend(redeemscript,n,pubkeyB);
#endif
    redeemscript[n++] = SCRIPT_OP_ENDIF;
    return(n);
}

int32_t basilisk_bobscript(uint8_t *rmd160,uint8_t *redeemscript,int32_t *redeemlenp,uint8_t *script,int32_t n,uint32_t *locktimep,int32_t *secretstartp,struct basilisk_swapinfo *swap,int32_t depositflag)
{
    if ( depositflag != 0 )
        *locktimep = swap->started + swap->putduration + swap->callduration;
    else *locktimep = swap->started + swap->putduration;
    *redeemlenp = n = basilisk_swap_bobredeemscript(depositflag,secretstartp,redeemscript,*locktimep,swap->pubA0,swap->pubB0,swap->pubB1,swap->privAm,swap->privBn,swap->secretAm,swap->secretAm256,swap->secretBn,swap->secretBn256);
    if ( n > 0 )
    {
        calc_rmd160_sha256(rmd160,redeemscript,n);
        n = bitcoin_p2shspend(script,0,rmd160);
        //for (i=0; i<n; i++)
        //    printf("%02x",script[i]);
        //char str[65]; printf(" <- redeem.%d bobtx dflag.%d %s\n",n,depositflag,bits256_str(str,cltvpub));
    }
    return(n);
}

int32_t basilisk_swapuserdata(uint8_t *userdata,bits256 privkey,int32_t ifpath,bits256 signpriv,uint8_t *redeemscript,int32_t redeemlen)
{
    int32_t i,len = 0;
#ifdef DISABLE_CHECKSIG
    userdata[len++] = sizeof(signpriv);
    for (i=0; i<sizeof(privkey); i++)
        userdata[len++] = signpriv.bytes[i];
#endif
    if ( bits256_nonz(privkey) != 0 )
    {
        userdata[len++] = sizeof(privkey);
        for (i=0; i<sizeof(privkey); i++)
            userdata[len++] = privkey.bytes[i];
    }
    userdata[len++] = 0x51 * ifpath; // ifpath == 1 -> if path, 0 -> else path
    return(len);
}

/*Bob paytx:
 OP_IF
 <now + INSTANTDEX_LOCKTIME> OP_CLTV OP_DROP <bob_pubB1> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <alice_pubA0> OP_CHECKSIG
 OP_ENDIF*/

int32_t basilisk_bobpayment_reclaim(struct basilisk_swap *swap,int32_t delay)
{
    uint8_t userdata[512]; int32_t i,retval,len = 0; static bits256 zero;
    printf("basilisk_bobpayment_reclaim\n");
    len = basilisk_swapuserdata(userdata,zero,1,swap->I.myprivs[1],swap->bobpayment.redeemscript,swap->bobpayment.I.redeemlen);
    memcpy(swap->I.userdata_bobreclaim,userdata,len);
    swap->I.userdata_bobreclaimlen = len;
    if ( (retval= basilisk_rawtx_sign(swap->bobcoin.symbol,swap->bobcoin.pubtype,swap->bobcoin.p2shtype,swap->bobcoin.isPoS,swap->bobcoin.wiftype,swap,&swap->bobreclaim,&swap->bobpayment,swap->I.myprivs[1],0,userdata,len,1)) == 0 )
    {
        for (i=0; i<swap->bobreclaim.I.datalen; i++)
            printf("%02x",swap->bobreclaim.txbytes[i]);
        printf(" <- bobreclaim\n");
        //basilisk_txlog(swap,&swap->bobreclaim,delay);
        return(retval);
    }
    return(-1);
}

int32_t basilisk_rawtx_spendscript(struct basilisk_swap *swap,int32_t height,struct basilisk_rawtx *rawtx,int32_t v,uint8_t *recvbuf,int32_t recvlen,int32_t suppress_pubkeys)
{
    int32_t datalen=0,retval=-1,hexlen,n; uint8_t *data; cJSON *txobj,*skey,*vouts,*vout; char *hexstr; bits256 txid;
    datalen = recvbuf[0];
    datalen += (int32_t)recvbuf[1] << 8;
    if ( datalen > 65536 )
        return(-1);
    rawtx->I.redeemlen = recvbuf[2];
    data = &recvbuf[3];
    if ( rawtx->I.redeemlen > 0 && rawtx->I.redeemlen < 0x100 )
        memcpy(rawtx->redeemscript,&data[datalen],rawtx->I.redeemlen);
    //printf("recvlen.%d datalen.%d redeemlen.%d\n",recvlen,datalen,rawtx->redeemlen);
    if ( rawtx->I.datalen == 0 )
    {
        //rawtx->txbytes = calloc(1,datalen);
        memcpy(rawtx->txbytes,data,datalen);
        rawtx->I.datalen = datalen;
    }
    else if ( datalen != rawtx->I.datalen || memcmp(rawtx->txbytes,data,datalen) != 0 )
    {
        int32_t i; for (i=0; i<datalen; i++)
            printf("%02x",data[i]);
        printf(" <- received\n");
        for (i=0; i<rawtx->I.datalen; i++)
            printf("%02x",rawtx->txbytes[i]);
        printf(" <- rawtx\n");
        printf("%s rawtx data compare error, len %d vs %d <<<<<<<<<< warning\n",rawtx->name,rawtx->I.datalen,datalen);
        return(-1);
    }
    txid = bits256_doublesha256(0,data,datalen);
    char str[65]; printf("rawtx.%s txid %s\n",rawtx->name,bits256_str(str,txid));
    if ( bits256_cmp(txid,rawtx->I.actualtxid) != 0 && bits256_nonz(rawtx->I.actualtxid) == 0 )
        rawtx->I.actualtxid = txid;
    if ( (txobj= bitcoin_data2json(rawtx->coin->pubtype,rawtx->coin->p2shtype,rawtx->coin->isPoS,height,&rawtx->I.signedtxid,&rawtx->msgtx,rawtx->extraspace,sizeof(rawtx->extraspace),data,datalen,0,suppress_pubkeys)) != 0 )
    {
        rawtx->I.actualtxid = rawtx->I.signedtxid;
        //char str[65]; printf("got txid.%s (%s)\n",bits256_str(str,rawtx->signedtxid),jprint(txobj,0));
        rawtx->I.locktime = rawtx->msgtx.lock_time;
        if ( (vouts= jarray(&n,txobj,"vout")) != 0 && v < n )
        {
            vout = jitem(vouts,v);
            if ( j64bits(vout,"satoshis") == rawtx->I.amount && (skey= jobj(vout,"scriptPubKey")) != 0 && (hexstr= jstr(skey,"hex")) != 0 )
            {
                if ( (hexlen= (int32_t)strlen(hexstr) >> 1) < sizeof(rawtx->spendscript) )
                {
                    decode_hex(rawtx->spendscript,hexlen,hexstr);
                    rawtx->I.spendlen = hexlen;
                    bitcoin_address(rawtx->p2shaddr,rawtx->coin->p2shtype,rawtx->spendscript,hexlen);
                    //if ( swap != 0 )
                    //    basilisk_txlog(swap->myinfoptr,swap,rawtx,-1); // bobdeposit, bobpayment or alicepayment
                    retval = 0;
                }
            } else printf("%s ERROR.(%s)\n",rawtx->name,jprint(txobj,0));
        }
        free_json(txobj);
    }
    return(retval);
}

int32_t basilisk_verify_bobpaid(void *ptr,uint8_t *data,int32_t datalen)
{
    uint8_t userdata[512]; int32_t i,retval,len = 0; bits256 revAm; struct basilisk_swap *swap = ptr;
    memset(revAm.bytes,0,sizeof(revAm));
    if ( basilisk_rawtx_spendscript(swap,swap->bobcoin.longestchain,&swap->bobpayment,0,data,datalen,0) == 0 )
    {
        swap->bobpayment.I.signedtxid = LP_broadcast_tx(swap->bobpayment.name,swap->bobpayment.coin->symbol,swap->bobpayment.txbytes,swap->bobpayment.I.datalen);
        if ( bits256_nonz(swap->bobpayment.I.signedtxid) != 0 )
            swap->paymentunconf = 1;
        basilisk_dontforget_update(swap,&swap->bobpayment);
        for (i=0; i<32; i++)
            revAm.bytes[i] = swap->I.privAm.bytes[31-i];
        len = basilisk_swapuserdata(userdata,revAm,0,swap->I.myprivs[0],swap->bobpayment.redeemscript,swap->bobpayment.I.redeemlen);
        memcpy(swap->I.userdata_alicespend,userdata,len);
        swap->I.userdata_alicespendlen = len;
        char str[65],str2[65]; printf("bobpaid privAm.(%s) myprivs[0].(%s)\n",bits256_str(str,swap->I.privAm),bits256_str(str2,swap->I.myprivs[0]));
        if ( (retval= basilisk_rawtx_sign(swap->bobcoin.symbol,swap->bobcoin.pubtype,swap->bobcoin.p2shtype,swap->bobcoin.isPoS,swap->bobcoin.wiftype,swap,&swap->alicespend,&swap->bobpayment,swap->I.myprivs[0],0,userdata,len,1)) == 0 )
        {
            for (i=0; i<swap->bobpayment.I.datalen; i++)
                printf("%02x",swap->bobpayment.txbytes[i]);
            printf(" <- bobpayment\n");
            for (i=0; i<swap->alicespend.I.datalen; i++)
                printf("%02x",swap->alicespend.txbytes[i]);
            printf(" <- alicespend\n\n");
            swap->I.alicespent = 1;
            //basilisk_txlog(swap,&swap->alicespend,-1);
            return(retval);
        }
    }
    return(-1);
}

int32_t basilisk_bobdeposit_refund(struct basilisk_swap *swap,int32_t delay)
{
    uint8_t userdata[512]; int32_t i,retval,len = 0; char str[65];
    len = basilisk_swapuserdata(userdata,swap->I.privBn,0,swap->I.myprivs[0],swap->bobdeposit.redeemscript,swap->bobdeposit.I.redeemlen);
    memcpy(swap->I.userdata_bobrefund,userdata,len);
    swap->I.userdata_bobrefundlen = len;
    if ( (retval= basilisk_rawtx_sign(swap->bobcoin.symbol,swap->bobcoin.pubtype,swap->bobcoin.p2shtype,swap->bobcoin.isPoS,swap->bobcoin.wiftype,swap,&swap->bobrefund,&swap->bobdeposit,swap->I.myprivs[0],0,userdata,len,0)) == 0 )
    {
        for (i=0; i<swap->bobrefund.I.datalen; i++)
            printf("%02x",swap->bobrefund.txbytes[i]);
        printf(" <- bobrefund.(%s)\n",bits256_str(str,swap->bobrefund.I.txid));
        //basilisk_txlog(swap,&swap->bobrefund,delay);
        return(retval);
    }
    return(-1);
}

int32_t basilisk_bobscripts_set(struct basilisk_swap *swap,int32_t depositflag,int32_t genflag)
{
    int32_t i,j; //char str[65];
    if ( genflag != 0 && swap->I.iambob == 0 )
        printf("basilisk_bobscripts_set WARNING: alice generating BOB tx\n");
    if ( depositflag == 0 )
    {
        swap->bobpayment.I.spendlen = basilisk_bobscript(swap->bobpayment.I.rmd160,swap->bobpayment.redeemscript,&swap->bobpayment.I.redeemlen,swap->bobpayment.spendscript,0,&swap->bobpayment.I.locktime,&swap->bobpayment.I.secretstart,&swap->I,0);
        bitcoin_address(swap->bobpayment.p2shaddr,swap->bobcoin.p2shtype,swap->bobpayment.redeemscript,swap->bobpayment.I.redeemlen);
        //for (i=0; i<swap->bobpayment.redeemlen; i++)
        //    printf("%02x",swap->bobpayment.redeemscript[i]);
        //printf(" <- bobpayment.%d\n",i);
        if ( genflag != 0 && bits256_nonz(*(bits256 *)swap->I.secretBn256) != 0 && swap->bobpayment.I.datalen == 0 )
        {
            for (i=0; i<3; i++)
            {
                //if ( swap->bobpayment.txbytes != 0 && swap->bobpayment.I.spendlen != 0 )
                //    break;
                basilisk_rawtx_gen(swap->ctx,"payment",swap->I.started,swap->persistent_pubkey33,1,1,&swap->bobpayment,swap->bobpayment.I.locktime,swap->bobpayment.spendscript,swap->bobpayment.I.spendlen,swap->bobpayment.coin->txfee,1,0,swap->persistent_privkey);
                if ( swap->bobpayment.I.spendlen == 0 || swap->bobpayment.I.datalen == 0 )
                {
                    printf("error bob generating %p payment.%d\n",swap->bobpayment.txbytes,swap->bobpayment.I.spendlen);
                    sleep(DEX_SLEEP);
                }
                else
                {
                    for (j=0; j<swap->bobpayment.I.datalen; j++)
                        printf("%02x",swap->bobpayment.txbytes[j]);
                    //printf(" <- bobpayment.%d\n",swap->bobpayment.datalen);
                    //for (j=0; j<swap->bobpayment.redeemlen; j++)
                    //    printf("%02x",swap->bobpayment.redeemscript[j]);
                    //printf(" <- redeem.%d\n",swap->bobpayment.redeemlen);
                    printf(" <- GENERATED BOB PAYMENT.%d\n",swap->bobpayment.I.datalen);
                    LP_unspents_mark(swap->bobcoin.symbol,swap->bobpayment.vins);
                    basilisk_bobpayment_reclaim(swap,swap->I.callduration);
                    printf("bobscripts set completed\n");
                    return(0);
                }
            }
        }
    }
    else
    {
        swap->bobdeposit.I.spendlen = basilisk_bobscript(swap->bobdeposit.I.rmd160,swap->bobdeposit.redeemscript,&swap->bobdeposit.I.redeemlen,swap->bobdeposit.spendscript,0,&swap->bobdeposit.I.locktime,&swap->bobdeposit.I.secretstart,&swap->I,1);
        bitcoin_address(swap->bobdeposit.p2shaddr,swap->bobcoin.p2shtype,swap->bobdeposit.redeemscript,swap->bobdeposit.I.redeemlen);
        if ( genflag != 0 && (swap->bobdeposit.I.datalen == 0 || swap->bobrefund.I.datalen == 0) )
        {
            for (i=0; i<3; i++)
            {
                //if ( swap->bobdeposit.txbytes != 0 && swap->bobdeposit.I.spendlen != 0 )
                //    break;
                basilisk_rawtx_gen(swap->ctx,"deposit",swap->I.started,swap->persistent_pubkey33,1,1,&swap->bobdeposit,swap->bobdeposit.I.locktime,swap->bobdeposit.spendscript,swap->bobdeposit.I.spendlen,swap->bobdeposit.coin->txfee,1,0,swap->persistent_privkey);
                if ( swap->bobdeposit.I.datalen == 0 || swap->bobdeposit.I.spendlen == 0 )
                {
                    printf("error bob generating %p deposit.%d\n",swap->bobdeposit.txbytes,swap->bobdeposit.I.spendlen);
                    sleep(DEX_SLEEP);
                }
                else
                {
                    for (j=0; j<swap->bobdeposit.I.datalen; j++)
                        printf("%02x",swap->bobdeposit.txbytes[j]);
                    printf(" <- GENERATED BOB DEPOSIT.%d\n",swap->bobdeposit.I.datalen);
                    //for (j=0; j<swap->bobdeposit.redeemlen; j++)
                    //    printf("%02x",swap->bobdeposit.redeemscript[j]);
                    //printf(" <- redeem.%d\n",swap->bobdeposit.redeemlen);
                    //printf("GENERATED BOB DEPOSIT\n");
                    LP_unspents_mark(swap->bobcoin.symbol,swap->bobdeposit.vins);
                    basilisk_bobdeposit_refund(swap,swap->I.putduration);
                    printf("bobscripts set completed\n");
                    return(0);
                }
            }
        }
        //for (i=0; i<swap->bobdeposit.redeemlen; i++)
        //    printf("%02x",swap->bobdeposit.redeemscript[i]);
        //printf(" <- bobdeposit.%d\n",i);
    }
    return(0);
}

/**/

struct basilisk_rawtx *LP_swapdata_rawtx(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx)
{
    if ( rawtx->I.datalen != 0 && rawtx->I.datalen <= maxlen )
    {
        memcpy(data,rawtx->txbytes,rawtx->I.datalen);
        return(rawtx);
    }
    return(0);
}

uint32_t LP_swapdata_rawtxsend(struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx,uint32_t nextbits,int32_t suppress_swapsend)
{
    uint8_t sendbuf[32768]; int32_t sendlen;
    if ( LP_swapdata_rawtx(swap,data,maxlen,rawtx) != 0 )
    {
        if ( bits256_nonz(rawtx->I.signedtxid) != 0 && bits256_nonz(rawtx->I.actualtxid) == 0 )
        {
            char str[65],str2[65];
            rawtx->I.actualtxid = LP_broadcast_tx(rawtx->name,rawtx->coin->symbol,rawtx->txbytes,rawtx->I.datalen);
            if ( bits256_cmp(rawtx->I.actualtxid,rawtx->I.signedtxid) != 0 )
            {
                printf("%s rawtxsend %s vs %s\n",rawtx->name,bits256_str(str,rawtx->I.signedtxid),bits256_str(str2,rawtx->I.actualtxid));
                rawtx->I.actualtxid = rawtx->I.signedtxid;
            }
            if ( bits256_nonz(rawtx->I.actualtxid) != 0 && msgbits != 0 )
            {
                sendlen = 0;
                sendbuf[sendlen++] = rawtx->I.datalen & 0xff;
                sendbuf[sendlen++] = (rawtx->I.datalen >> 8) & 0xff;
                sendbuf[sendlen++] = rawtx->I.redeemlen;
                memcpy(&sendbuf[sendlen],rawtx->txbytes,rawtx->I.datalen), sendlen += rawtx->I.datalen;
                if ( rawtx->I.redeemlen > 0 && rawtx->I.redeemlen < 0x100 )
                {
                    memcpy(&sendbuf[sendlen],rawtx->redeemscript,rawtx->I.redeemlen);
                    sendlen += rawtx->I.redeemlen;
                }
                basilisk_dontforget_update(swap,rawtx);
                //printf("sendlen.%d datalen.%d redeemlen.%d\n",sendlen,rawtx->datalen,rawtx->redeemlen);
                if ( suppress_swapsend == 0 )
                    return(LP_swapsend(swap,msgbits,sendbuf,sendlen,nextbits,rawtx->I.crcs));
                else
                {
                    printf("suppress swapsend %x\n",msgbits);
                    return(0);
                }
            }
        }
        return(nextbits);
    } else if ( swap->I.iambob == 0 )
        printf("error from basilisk_swapdata_rawtx.%s %p len.%d\n",rawtx->name,rawtx->txbytes,rawtx->I.datalen);
    return(0);
}

void basilisk_swap_coinaddr(struct basilisk_swap *swap,struct iguana_info *coin,char *coinaddr,uint8_t *data,int32_t datalen)
{
    cJSON *txobj,*vouts,*vout,*addresses,*item,*skey; uint8_t extraspace[8192]; bits256 signedtxid; struct iguana_msgtx msgtx; char *addr; int32_t n,m,suppress_pubkeys = 0;
    if ( (txobj= bitcoin_data2json(coin->pubtype,coin->p2shtype,coin->isPoS,coin->longestchain,&signedtxid,&msgtx,extraspace,sizeof(extraspace),data,datalen,0,suppress_pubkeys)) != 0 )
    {
        //char str[65]; printf("got txid.%s (%s)\n",bits256_str(str,signedtxid),jprint(txobj,0));
        if ( (vouts= jarray(&n,txobj,"vout")) != 0 && n > 0 )
        {
            vout = jitem(vouts,0);
            //printf("VOUT.(%s)\n",jprint(vout,0));
            if ( (skey= jobj(vout,"scriptPubKey")) != 0 && (addresses= jarray(&m,skey,"addresses")) != 0 )
            {
                item = jitem(addresses,0);
                //printf("item.(%s)\n",jprint(item,0));
                if ( (addr= jstr(item,0)) != 0 )
                {
                    safecopy(coinaddr,addr,64);
                    //printf("extracted.(%s)\n",coinaddr);
                }
            }
        }
        free_json(txobj);
    }
}

int32_t basilisk_verify_otherfee(void *ptr,uint8_t *data,int32_t datalen)
{
    struct basilisk_swap *swap = ptr;
    // add verification and broadcast
    //swap->otherfee.txbytes = calloc(1,datalen);
    memcpy(swap->otherfee.txbytes,data,datalen);
    swap->otherfee.I.datalen = datalen;
    swap->otherfee.I.actualtxid = swap->otherfee.I.signedtxid = bits256_doublesha256(0,data,datalen);
    //basilisk_txlog(swap,&swap->otherfee,-1);
    return(0);
}

/*    Bob deposit:
 OP_IF
 <now + INSTANTDEX_LOCKTIME*2> OP_CLTV OP_DROP <alice_pubA0> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY <bob_pubB0> OP_CHECKSIG
 OP_ENDIF*/

int32_t basilisk_verify_bobdeposit(void *ptr,uint8_t *data,int32_t datalen)
{
    uint8_t userdata[512]; int32_t i,retval,len = 0; static bits256 zero; struct basilisk_swap *swap = ptr;
    if ( basilisk_rawtx_spendscript(swap,swap->bobcoin.longestchain,&swap->bobdeposit,0,data,datalen,0) == 0 )
    {
        swap->bobdeposit.I.signedtxid = LP_broadcast_tx(swap->bobdeposit.name,swap->bobcoin.symbol,swap->bobdeposit.txbytes,swap->bobdeposit.I.datalen);
        if ( bits256_nonz(swap->bobdeposit.I.signedtxid) != 0 )
            swap->depositunconf = 1;
        basilisk_dontforget_update(swap,&swap->bobdeposit);
        len = basilisk_swapuserdata(userdata,zero,1,swap->I.myprivs[0],swap->bobdeposit.redeemscript,swap->bobdeposit.I.redeemlen);
        memcpy(swap->I.userdata_aliceclaim,userdata,len);
        swap->I.userdata_aliceclaimlen = len;
        if ( (retval= basilisk_rawtx_sign(swap->bobcoin.symbol,swap->bobcoin.pubtype,swap->bobcoin.p2shtype,swap->bobcoin.isPoS,swap->bobcoin.wiftype,swap,&swap->aliceclaim,&swap->bobdeposit,swap->I.myprivs[0],0,userdata,len,1)) == 0 )
        {
            for (i=0; i<swap->bobdeposit.I.datalen; i++)
                printf("%02x",swap->bobdeposit.txbytes[i]);
            printf(" <- bobdeposit\n");
            for (i=0; i<swap->aliceclaim.I.datalen; i++)
                printf("%02x",swap->aliceclaim.txbytes[i]);
            printf(" <- aliceclaim\n");
            //basilisk_txlog(swap,&swap->aliceclaim,swap->I.putduration+swap->I.callduration);
            return(retval);
        }
    }
    printf("error with bobdeposit\n");
    return(-1);
}

void basilisk_alicepayment(struct basilisk_swap *swap,struct iguana_info *coin,struct basilisk_rawtx *alicepayment,bits256 pubAm,bits256 pubBn)
{
    alicepayment->I.spendlen = basilisk_alicescript(alicepayment->redeemscript,&alicepayment->I.redeemlen,alicepayment->spendscript,0,alicepayment->I.destaddr,coin->p2shtype,pubAm,pubBn);
    basilisk_rawtx_gen(swap->ctx,"alicepayment",swap->I.started,swap->persistent_pubkey33,0,1,alicepayment,alicepayment->I.locktime,alicepayment->spendscript,alicepayment->I.spendlen,coin->txfee,1,0,swap->persistent_privkey);
}

int32_t basilisk_alicepayment_spend(struct basilisk_swap *swap,struct basilisk_rawtx *dest)
{
    int32_t i,retval;
    printf("alicepayment_spend\n");
    swap->alicepayment.I.spendlen = basilisk_alicescript(swap->alicepayment.redeemscript,&swap->alicepayment.I.redeemlen,swap->alicepayment.spendscript,0,swap->alicepayment.I.destaddr,swap->alicecoin.p2shtype,swap->I.pubAm,swap->I.pubBn);
    printf("alicepayment_spend len.%d\n",swap->alicepayment.I.spendlen);
    if ( swap->I.iambob == 0 )
    {
        memcpy(swap->I.userdata_alicereclaim,swap->alicepayment.redeemscript,swap->alicepayment.I.spendlen);
        swap->I.userdata_alicereclaimlen = swap->alicepayment.I.spendlen;
    }
    else
    {
        memcpy(swap->I.userdata_bobspend,swap->alicepayment.redeemscript,swap->alicepayment.I.spendlen);
        swap->I.userdata_bobspendlen = swap->alicepayment.I.spendlen;
    }
    if ( (retval= basilisk_rawtx_sign(swap->alicecoin.symbol,swap->alicecoin.pubtype,swap->alicecoin.p2shtype,swap->alicecoin.isPoS,swap->alicecoin.wiftype,swap,dest,&swap->alicepayment,swap->I.privAm,&swap->I.privBn,0,0,1)) == 0 )
    {
        for (i=0; i<dest->I.datalen; i++)
            printf("%02x",dest->txbytes[i]);
        printf(" <- msigspend\n\n");
        if ( dest == &swap->bobspend )
            swap->I.bobspent = 1;
        //basilisk_txlog(swap,dest,0); // bobspend or alicereclaim
        return(retval);
    }
    return(-1);
}

int32_t basilisk_verify_alicepaid(void *ptr,uint8_t *data,int32_t datalen)
{
    struct basilisk_swap *swap = ptr;
    if ( basilisk_rawtx_spendscript(swap,swap->alicecoin.longestchain,&swap->alicepayment,0,data,datalen,0) == 0 )
    {
        swap->alicepayment.I.signedtxid = LP_broadcast_tx(swap->alicepayment.name,swap->alicecoin.symbol,swap->alicepayment.txbytes,swap->alicepayment.I.datalen);
        if ( bits256_nonz(swap->alicepayment.I.signedtxid) != 0 )
            swap->aliceunconf = 1;
        basilisk_dontforget_update(swap,&swap->alicepayment);
        return(0);
    }
    else return(-1);
}

int32_t basilisk_alicetxs(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,retval = -1;
    printf("alicetxs\n");
    for (i=0; i<3; i++)
    {
        if ( swap->alicepayment.I.datalen == 0 )
            basilisk_alicepayment(swap,swap->alicepayment.coin,&swap->alicepayment,swap->I.pubAm,swap->I.pubBn);
        if ( swap->alicepayment.I.datalen == 0 || swap->alicepayment.I.spendlen == 0 )
        {
            printf("error alice generating payment.%d\n",swap->alicepayment.I.spendlen);
            sleep(20);
        }
        else
        {
            retval = 0;
            for (i=0; i<swap->alicepayment.I.datalen; i++)
                printf("%02x",swap->alicepayment.txbytes[i]);
            printf(" ALICE PAYMENT created\n");
            LP_unspents_mark(swap->alicecoin.symbol,swap->alicepayment.vins);
            //basilisk_txlog(swap,&swap->alicepayment,-1);
            break;
        }
    }
    if ( swap->myfee.I.datalen == 0 )
    {
        printf("generate fee\n");
        if ( basilisk_rawtx_gen(swap->ctx,"myfee",swap->I.started,swap->persistent_pubkey33,swap->I.iambob,1,&swap->myfee,0,swap->myfee.spendscript,swap->myfee.I.spendlen,swap->myfee.coin->txfee,1,0,swap->persistent_privkey) == 0 )
        {
            swap->I.statebits |= LP_swapdata_rawtxsend(swap,0x80,data,maxlen,&swap->myfee,0x40,0);
            LP_unspents_mark(swap->I.iambob!=0?swap->bobcoin.symbol:swap->alicecoin.symbol,swap->myfee.vins);
            //basilisk_txlog(swap,&swap->myfee,-1);
            for (i=0; i<swap->myfee.I.spendlen; i++)
                printf("%02x",swap->myfee.txbytes[i]);
            printf(" fee %p %x\n",swap->myfee.txbytes,swap->I.statebits);
            swap->I.statebits |= 0x40;
        }
        else
        {
            printf("error creating myfee\n");
            return(-2);
        }
    }
    if ( swap->alicepayment.I.datalen != 0 && swap->alicepayment.I.spendlen > 0 && swap->myfee.I.datalen != 0 && swap->myfee.I.spendlen > 0 )
        return(0);
    return(-1);
}
