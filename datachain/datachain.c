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
        datachain_events_rewind(myinfo,myinfo->dPOW.BTCD.events,myinfo->dPOW.BTCD.numevents,height,hdrsi,unspentind);
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
        datachain_events_rewind(myinfo,virt->dPOW.events,virt->dPOW.numevents,height,hdrsi,unspentind);
    }
    else
    {
        // new virt block actions
        printf("NEWBLOCK.%s ht.%d\n",virt->symbol,height);
    }
    virt->dPOW.lasthdrsi = hdrsi;
    virt->dPOW.lastunspentind = unspentind;
}

void datachain_opreturn(struct supernet_info *myinfo,struct iguana_info *coin,int32_t btc_or_btcd,int64_t crypto777_payment,int64_t burned,int32_t height,uint64_t hdrsi_unspentind,uint8_t *data,int32_t datalen)
{
    uint32_t hdrsi,unspentind;
    hdrsi = (uint32_t)(hdrsi_unspentind >> 32);
    unspentind = (uint32_t)hdrsi_unspentind;
    if ( btc_or_btcd == 1 ) // BTC
    {
        if ( data == 0 )
            datachain_BTC_clock(myinfo,coin,height,hdrsi,unspentind);
        else
        {
            
        }
    }
    else if ( btc_or_btcd == 2 ) // BTCD
    {
        if ( data == 0 )
            datachain_BTCD_newblock(myinfo,coin,height,hdrsi,unspentind);
        else
        {
            
        }
    }
    else
    {
        if ( data == 0 )
            datachain_virt_newblock(myinfo,coin,height,hdrsi,unspentind);
        else
        {
            
        }
    }
}

int32_t iguana_opreturn(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,int64_t crypto777_payment,int32_t height,uint64_t hdrsi_unspentind,int64_t burned,uint32_t fileid,uint64_t scriptpos,uint32_t scriptlen)
{
    uint8_t scriptspace[IGUANA_MAXSCRIPTSIZE]; char fname[1024]; uint32_t datalen=0; int32_t btc_or_btcd=0,len = -1;
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
        if ( (len= iguana_scriptdata(coin,scriptspace,coin->voutptrs[fileid],fname,scriptpos,len)) == scriptlen )
        {
            if ( scriptspace[0] == 0x6a )
            {
                len = 1;
                if ( (datalen= scriptspace[len++]) >= 76 )
                {
                    if ( datalen == 0x4c )
                        datalen = scriptspace[len++];
                    else if ( datalen == 0x4d )
                    {
                        datalen = scriptspace[len++];
                        datalen = (datalen << 8) | scriptspace[len++];
                    }
                }
                if ( len+datalen == scriptlen )
                {
                    datachain_opreturn(myinfo,coin,btc_or_btcd,crypto777_payment,burned,height,hdrsi_unspentind,&scriptspace[len],datalen);
                    return(datalen);
                } else printf("len.%d + datalen.%d != scriptlen.%d\n",len,datalen,scriptlen);
            } else printf("not OP_RETURN.%02x scriptlen.%d\n",scriptspace[0],scriptlen);
        } else printf("iguana_opreturn error: %d bytes from fileid.%d[%d] %s for scriptlen.%d\n",len,fileid,(uint32_t)scriptpos,fname,scriptlen);
    }
    return(-1);
}
