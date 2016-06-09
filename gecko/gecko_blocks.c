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

// included from gecko.c

char *gecko_headersarrived(struct supernet_info *myinfo,struct iguana_info *virt,struct iguana_peer *addr,uint8_t *data,int32_t datalen)
{
    return(clonestr("{\"result\":\"gecko headers queued\"}"));
}

char *gecko_blockarrived(struct supernet_info *myinfo,struct iguana_info *virt,struct iguana_peer *addr,uint8_t *data,int32_t datalen)
{
    struct iguana_txblock txdata; int32_t n,len = -1; struct iguana_msghdr H;
    if ( virt->TXMEM.ptr == 0 )
        iguana_meminit(&virt->TXMEM,virt->name,0,IGUANA_MAXPACKETSIZE * 2,0);
    iguana_memreset(&virt->TXMEM);
    memset(&txdata,0,sizeof(txdata));
    if ( (n= iguana_gentxarray(virt,&virt->TXMEM,&txdata,&len,data,datalen)) == datalen )
    {
        memset(&H,0,sizeof(H));
        iguana_gotblockM(virt,addr,&txdata,virt->TXMEM.ptr,&H,data,datalen);
        return(clonestr("{\"result\":\"gecko block queued\"}"));
    } else return(clonestr("{\"error\":\"gecko block didnt decode\"}"));
}
