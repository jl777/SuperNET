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

#include "../iguana/iguana777.h"

int32_t datachain_rwgenesis(int32_t rwflag,uint8_t *serialized,struct gecko_genesis_opreturn *opret)
{
    int32_t len = 0;
    if ( rwflag == 0 )
    {
        memcpy(opret->type,&serialized[len],sizeof(opret->type)), len += sizeof(opret->type);
        memcpy(opret->symbol,&serialized[len],sizeof(opret->symbol)), len += sizeof(opret->symbol);
        memcpy(opret->name,&serialized[len],sizeof(opret->name)), len += sizeof(opret->name);
    }
    else
    {
        memcpy(&serialized[len],opret->type,sizeof(opret->type)), len += sizeof(opret->type);
        memcpy(&serialized[len],opret->symbol,sizeof(opret->symbol)), len += sizeof(opret->symbol);
        memcpy(&serialized[len],opret->name,sizeof(opret->name)), len += sizeof(opret->name);
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->PoSvalue),&opret->PoSvalue);
    //len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->flags),&opret->flags);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->netmagic),&opret->netmagic);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->timestamp),&opret->timestamp);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->nBits),&opret->nBits);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->nonce),&opret->nonce);
    //len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->extra),&opret->extra);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->blocktime),&opret->blocktime);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(opret->port),&opret->port);
    if ( rwflag == 0 )
    {
        opret->version = serialized[len++];
        opret->pubval = serialized[len++];
        opret->p2shval = serialized[len++];
        opret->wifval = serialized[len++];
        memcpy(opret->rmd160,&serialized[len],20), len += 20;
    }
    else
    {
        serialized[len++] = opret->version;
        serialized[len++] = opret->pubval;
        serialized[len++] = opret->p2shval;
        serialized[len++] = opret->wifval;
        memcpy(&serialized[len],opret->rmd160,20), len += 20;
    }
    printf("opreturn len.%d\n",len);
    return(len);
}

int32_t datachain_opreturn_create(uint8_t *serialized,char *symbol,char *name,char *coinaddr,int64_t PoSvalue,uint32_t nBits,uint16_t blocktime,uint16_t port,uint8_t p2shval,uint8_t wifval)
{
    uint8_t txidbytes[1024],minerpayment[512]; int32_t i,len,datalen,minerpaymentlen=0,txlen; struct gecko_genesis_opreturn opret; bits256 txid,zero,threshold,hash2; struct iguana_info *btcd; char coinbasestr[512]; struct iguana_msgblock msg;
    btcd = iguana_coinfind("BTCD");
    memset(&opret,0,sizeof(opret));
    opret.type[0] = 'N', opret.type[1] = 'E', opret.type[2] = 'W';
    memcpy(opret.symbol,symbol,sizeof(opret.symbol));
    memcpy(opret.name,name,sizeof(opret.name));
    opret.version = 1;
    opret.PoSvalue = PoSvalue;
    opret.nBits = nBits;
    opret.p2shval = p2shval;
    opret.wifval = wifval;
    opret.blocktime = blocktime;
    opret.port = port;
    opret.timestamp = (uint32_t)time(NULL);
    OS_randombytes((void *)&opret.netmagic,sizeof(opret.netmagic));
    bitcoin_addr2rmd160(&opret.pubval,opret.rmd160,coinaddr);
    if ( PoSvalue > 0 )
        minerpaymentlen = bitcoin_standardspend(minerpayment,0,opret.rmd160);
    memset(zero.bytes,0,sizeof(zero));
    sprintf(coinbasestr,"%s_%s",symbol,name);
    txlen = iguana_coinbase(btcd,txidbytes,opret.timestamp,zero,(uint8_t *)coinbasestr,(int32_t)strlen(coinbasestr)+1,minerpayment,minerpaymentlen,PoSvalue,&txid);
    memset(&msg,0,sizeof(msg));
    msg.H.version = opret.version;
    msg.H.merkle_root = txid;
    msg.H.timestamp = opret.timestamp;
    msg.H.bits = opret.nBits;
    threshold = bits256_from_compact(nBits);
    for (i=0; i<100000000; i++)
    {
        msg.H.nonce = i;
        datalen = iguana_rwblockhdr(1,0,serialized,&msg);
        hash2 = iguana_calcblockhash(symbol,btcd->chain->hashalgo,serialized,datalen);
        if ( bits256_cmp(threshold,hash2) > 0 )
            break;
    }
    len = datachain_rwgenesis(1,serialized,&opret);
    //for (i=0; i<len; i++)
    //    printf("%02x",serialized[i]);
    //printf(" <- opreturn\n");
    return(len);
}

int32_t datachain_datascript(struct iguana_info *coin,uint8_t *script,uint8_t *data,int32_t datalen)
{
    int32_t i,pkey0,plen,len = 0; uint8_t p2sh_rmd160[20]; struct vin_info V;
    memset(&V,0,sizeof(V));
    if ( len < 32*3 )
        pkey0 = 2, plen = 32;
    else pkey0 = 4, plen = 64;
    V.M = V.N = (datalen / plen) + ((datalen % plen) != 0);
    for (i=0; i<V.N; i++)
    {
        V.signers[i].pubkey[0] = pkey0;
        memcpy(V.signers[i].pubkey+1,&data[len],plen), len += plen;
    }
    return(bitcoin_MofNspendscript(p2sh_rmd160,script,0,&V));
}

int32_t datachain_datascript_decode(uint8_t *opreturn,uint8_t *script,int32_t scriptlen,struct vin_info *vp,int32_t type)
{
    int32_t plen,i,oplen=0;
    for (i=0; i<vp->N; i++)
    {
        if ( (plen= bitcoin_pubkeylen(vp->signers[i].pubkey)) > 32 )
            memcpy(&opreturn[oplen],vp->signers[i].pubkey+1,plen-1), oplen += (plen - 1);
    }
    return(oplen);
}

int32_t datachain_opreturnscript(struct iguana_info *coin,uint8_t *script,char *datastr,int32_t datalen)
{
    int32_t offset = 0;
    script[offset++] = 0x6a;
    if ( datalen >= 0x4c )
    {
        if ( datalen > 0xff )
        {
            script[offset++] = 0x4d;
            script[offset++] = datalen & 0xff;
            script[offset++] = (datalen >> 8) & 0xff;
        }
        else
        {
            script[offset++] = 0x4c;
            script[offset++] = datalen;
        }
    } else script[offset++] = datalen;
    decode_hex(&script[offset],datalen,datastr);
    return(datalen + offset);
}

int32_t datachain_opreturn_decode(uint8_t *opreturn,uint8_t *script,int32_t scriptlen)
{
    int32_t datalen,len = 1;
    if ( (datalen= script[len++]) >= 76 )
    {
        if ( datalen == 0x4c )
            datalen = script[len++];
        else if ( datalen == 0x4d )
        {
            datalen = script[len++];
            datalen = (datalen << 8) | script[len++];
        }
    }
    memcpy(opreturn,&script[len],datalen);
    if ( len+datalen == scriptlen )
        return(datalen);
    else return(-1);
}

int32_t datachain_events_rewind(struct supernet_info *myinfo,struct datachain_event *events,int32_t numevents,int32_t height,uint32_t hdrsi,uint32_t unspentind)
{
    return(numevents);
}

void datachain_BTC_clock(struct supernet_info *myinfo,struct iguana_info *btc,int32_t height,uint32_t hdrsi,uint32_t unspentind)
{
    if ( hdrsi < myinfo->dPOW.BTC.lasthdrsi || (hdrsi == myinfo->dPOW.BTC.lasthdrsi && unspentind < myinfo->dPOW.BTC.lastunspentind) )
    {
        myinfo->dPOW.BTC.numevents = datachain_events_rewind(myinfo,myinfo->dPOW.BTC.events,myinfo->dPOW.BTC.numevents,height,hdrsi,unspentind);
    }
    else
    {
        printf("NEWBLOCK.%s ht.%d\n",btc->symbol,height);
    }
    myinfo->dPOW.BTC.lasthdrsi = hdrsi;
    myinfo->dPOW.BTC.lastunspentind = unspentind;
}

void datachain_BTCD_newblock(struct supernet_info *myinfo,struct iguana_info *btcd,int32_t height,uint32_t hdrsi,uint32_t unspentind)
{
    if ( hdrsi < myinfo->dPOW.BTCD.lasthdrsi || (hdrsi == myinfo->dPOW.BTCD.lasthdrsi && unspentind < myinfo->dPOW.BTCD.lastunspentind) )
    {
        myinfo->dPOW.BTCD.numevents = datachain_events_rewind(myinfo,myinfo->dPOW.BTCD.events,myinfo->dPOW.BTCD.numevents,height,hdrsi,unspentind);
    }
    else
    {
        // new BTCD block actions
        printf("NEWBLOCK.%s ht.%d\n",btcd->symbol,height);
    }
    myinfo->dPOW.BTCD.lasthdrsi = hdrsi;
    myinfo->dPOW.BTCD.lastunspentind = unspentind;
}

void datachain_virt_newblock(struct supernet_info *myinfo,struct iguana_info *virt,int32_t height,uint32_t hdrsi,uint32_t unspentind)
{
    if ( hdrsi < virt->dPOW.lasthdrsi || (hdrsi == virt->dPOW.lasthdrsi && unspentind < virt->dPOW.lastunspentind) )
    {
        virt->dPOW.numevents = datachain_events_rewind(myinfo,virt->dPOW.events,virt->dPOW.numevents,height,hdrsi,unspentind);
    }
    else
    {
        // new virt block actions
        printf("NEWBLOCK.%s ht.%d\n",virt->symbol,height);
    }
    virt->dPOW.lasthdrsi = hdrsi;
    virt->dPOW.lastunspentind = unspentind;
}

void datachain_opreturn(struct supernet_info *myinfo,struct iguana_info *coin,int32_t btc_or_btcd,int64_t crypto777_payment,int64_t burned,int32_t height,uint64_t hdrsi_unspentind,uint8_t *opreturn,int32_t oplen)
{
    uint32_t hdrsi,unspentind;
    hdrsi = (uint32_t)(hdrsi_unspentind >> 32);
    unspentind = (uint32_t)hdrsi_unspentind;
    if ( btc_or_btcd == 1 ) // BTC
    {
        if ( opreturn == 0 )
            datachain_BTC_clock(myinfo,coin,height,hdrsi,unspentind);
        else
        {
            
        }
    }
    else if ( btc_or_btcd == 2 ) // BTCD
    {
        if ( opreturn == 0 )
            datachain_BTCD_newblock(myinfo,coin,height,hdrsi,unspentind);
        else
        {
            
        }
    }
    else
    {
        if ( opreturn == 0 )
            datachain_virt_newblock(myinfo,coin,height,hdrsi,unspentind);
        else
        {
            
        }
    }
    if ( opreturn != 0 )
    {
        int32_t i;
        for (i=0; i<oplen; i++)
            printf("%02x",opreturn[oplen]);
        printf(" <- opreturn.%s len.%d\n",coin->symbol,oplen);
    }
}

int32_t iguana_opreturn(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,int64_t crypto777_payment,int32_t height,uint64_t hdrsi_unspentind,int64_t burned,uint32_t fileid,uint64_t scriptpos,uint32_t scriptlen)
{
    uint8_t type,scriptspace[IGUANA_MAXSCRIPTSIZE],opreturn[8192]; char fname[1024]; uint32_t sigsize,pubkeysize,p2shsize,suffix,oplen=0; int32_t btc_or_btcd=0,len = -1; struct vin_info V;
    if ( strcmp("BTC",coin->symbol) == 0 )
        btc_or_btcd = 1;
    else if ( strcmp("BTCD",coin->symbol) == 0 )
        btc_or_btcd = 2;
    else if ( coin->virtualchain == 0 )
        return(-1);
    if ( height < bp->bundleheight || height >= bp->bundleheight+coin->chain->bundlesize )
    {
        printf("iguana_opreturn illegal height %d for [%d] %d\n",height,bp->hdrsi,bp->bundleheight);
        return(-1);
    }
    if ( crypto777_payment == 0 && burned == 0 && scriptlen == 0 && fileid == 0 && scriptpos == 0 )
    {
        datachain_opreturn(myinfo,coin,btc_or_btcd,crypto777_payment,burned,height,hdrsi_unspentind,0,0);
        return(0);
    }
    if ( scriptpos > 0 && scriptlen > 0 )
    {
        iguana_voutsfname(coin,bp->ramchain.from_ro,fname,fileid);
        if ( (len= iguana_scriptdata(coin,scriptspace,coin->voutptrs[fileid],fname,scriptpos,scriptlen)) == scriptlen )
        {
            memset(&V,0,sizeof(V));
            type = iguana_vinscriptparse(coin,&V,&sigsize,&pubkeysize,&p2shsize,&suffix,scriptspace,scriptlen);
            if ( type == IGUANA_SCRIPT_OPRETURN )
                oplen = datachain_opreturn_decode(opreturn,scriptspace,scriptlen);
            else oplen = datachain_datascript_decode(opreturn,scriptspace,scriptlen,&V,type);
            datachain_opreturn(myinfo,coin,btc_or_btcd,crypto777_payment,burned,height,hdrsi_unspentind,opreturn,oplen);
            return(oplen);
        } else printf("iguana_opreturn error: %d bytes from fileid.%d[%d] %s for scriptlen.%d\n",len,fileid,(uint32_t)scriptpos,fname,scriptlen);
    }
    return(-1);
}

int64_t datachain_update(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,uint8_t rmd160[20],int64_t crypto777_payment,uint8_t type,int32_t height,uint64_t hdrsi_unspentind,int64_t value,uint32_t fileid,uint64_t scriptpos,int32_t scriptlen)
{
    if ( memcmp(rmd160,CRYPTO777_RMD160,20) == 0 )
        crypto777_payment += value;
    else if ( crypto777_payment != 0 && (type == IGUANA_SCRIPT_OPRETURN || type == IGUANA_SCRIPT_3of3 || type == IGUANA_SCRIPT_2of2 || type == IGUANA_SCRIPT_1of1) )
    {
        iguana_opreturn(myinfo,coin,bp,crypto777_payment,height,hdrsi_unspentind,value,fileid,scriptpos,scriptlen);
    }
    return(crypto777_payment);
}