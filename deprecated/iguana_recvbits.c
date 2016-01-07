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

#include "iguana777.h"

int64_t iguana_packetsallocated(struct iguana_info *coin) { return(coin->R.packetsallocated - coin->R.packetsfreed); };

uint8_t *iguana_decompress(struct iguana_info *coin,int32_t height,int32_t *datalenp,uint8_t *bits,int32_t numbits,int32_t origdatalen)
{
    uint32_t hdrlen,checklen;
    memcpy(&hdrlen,bits,sizeof(hdrlen));
    bits = &bits[sizeof(hdrlen)];
    *datalenp = 0;
    if ( (hdrlen & (1 << 31)) != 0 )
    {
        hdrlen ^= (1 << 31);
        if ( (hdrlen >> 3) == origdatalen )
        {
            *datalenp = origdatalen;
            return(bits);
        } else printf("\n>>>>>>>>> iguana_decompress.%d numbits.%d %d != origlen.%d\n",height,hdrlen,hdrlen>>3,origdatalen), getchar();
    }
    else if ( hconv_bitlen(hdrlen) == hconv_bitlen(numbits) )
    {
        if ( (checklen= ramcoder_decompress(coin->R.decompressed,sizeof(coin->R.decompressed),bits,hdrlen,bits256_zero)) == origdatalen )
        {
            //printf("DECOMPRESSED %d to %d\n",hconv_bitlen(hdrlen),checklen);
            *datalenp = origdatalen;
            return(coin->R.decompressed);
        }
        else
        {
            printf("\n>>>>>>>>> iguana_decompress.%d hdrlen.%d checklen.%d != origdatalen.%d\n",height,hdrlen,checklen,origdatalen);
            int32_t j;
            for (j=0; j<hconv_bitlen(numbits); j++)
                printf("%02x ",bits[j]);
            printf("compressed.%d\n",numbits/8);
            getchar();
        }
    }
    else
    {
        printf("\n>>>>>>>>>> iguana_decompress.%d hdrlen.%d != numbits.%d\n",height,hdrlen,numbits);
        int32_t j;
        for (j=0; j<=numbits/8; j++)
            printf("%02x ",bits[j]);
        printf("compressed.%d\n",numbits/8);
        getchar();
    }
    return(0);
}

/*struct iguana_msgtx *iguana_validpending(struct iguana_info *coin,struct iguana_pending *ptr,struct iguana_block *space)
{
    struct iguana_block *checkblock; uint8_t *data; int32_t datalen,len; struct iguana_msgtx *tx = 0;
    *space = ptr->block;
    if ( coin->R.recvblocks == 0 || ptr->block.height >= coin->R.numwaitingbits )
    {
        printf("illegal pending height.%d vs %d\n",ptr->block.height,coin->R.numwaitingbits);
        return(0);
    }
    if ( ptr->origdatalen > 0 && ptr->block.height < coin->longestchain && ptr->block.height < coin->blocks.hwmheight )
    {
        if ( (checkblock= iguana_block(coin,space,ptr->block.height)) != 0 )
        {
            if ( iguana_blockcmp(coin,checkblock,space,1) == 0 )
            {
                data = iguana_decompress(coin,ptr->block.height,&datalen,ptr->data,ptr->datalen << 3,ptr->origdatalen);
                //printf("parsed.%d vs max.%d height.%d data.%p\n",coin->blocks.parsedblocks,coin->R.numwaitingbits,ptr->block.height,data);
                if ( data != 0 && iguana_setdependencies(coin,space) == ptr->block.height )
                {
                    if ( (tx= iguana_gentxarray(coin,&len,space,data,datalen)) != 0 && len == datalen )
                        return(tx);
                } else printf("iguana_validpending: error gentx block.%d\n",coin->blocks.parsedblocks);
            } else printf("iguana_validpending: error setting vars block.%d\n",ptr->block.height);
            if ( tx != 0 )
                iguana_freetx(tx,ptr->numtx);
        } else printf("iguana_validpending cant get checkblock %d vs hwmheight.%d\n",ptr->block.height,coin->blocks.hwmheight);
    }
    return(0);
}*/

/*int32_t iguana_processrecv(struct iguana_info *coin)
{
    int32_t height; struct iguana_block space; struct iguana_msgtx *tx = 0;
    struct iguana_pending *ptr = 0; int32_t retval = -1;
    height = coin->blocks.parsedblocks;
    if ( coin->R.recvblocks != 0 && height < coin->R.numwaitingbits )
    {
        if ( (ptr= coin->R.recvblocks[height]) != 0 )
        {
            //printf("iguana_processrecv height.%d %p\n",height,ptr);
            coin->R.recvblocks[height] = 0;
            if ( (tx= iguana_validpending(coin,ptr,&space)) != 0 )
            {
                retval = iguana_parseblock(coin,&space,tx,ptr->numtx);
                if ( space.L.numunspents+space.numvouts != coin->latest.dep.numunspents )
                    printf("block->firstvout+block->numvouts (%d+%d) != %d coin->latest.deps.numunspentinds\n",space.L.numunspents,space.numvouts,coin->latest.dep.numunspents), getchar();
                if ( retval < 0 )
                    printf("iguana_processrecv: error parsing block.%d tx.%p\n",ptr->block.height,tx);
                if ( tx != 0 )
                    iguana_freetx(tx,ptr->numtx);
            } else printf("error getting pending %d %p\n",height,ptr);
            if ( coin->R.maprecvdata == 0 )
            {
                coin->R.packetsfreed += ptr->allocsize;
                myfree(ptr,ptr->allocsize);
            }
        }
        else if ( time(NULL) > coin->parsetime+1 )
        {
            coin->parsetime = (uint32_t)time(NULL);
            printf("backstop.%d %s\n",height,bits256_str(iguana_blockhash(coin,height)));
            bits256 hash2 = iguana_blockhash(coin,height);
            iguana_request_data(coin,coin->peers.ranked[0],&hash2,1,MSG_BLOCK,1);
            iguana_waitclear(coin,height);
            iguana_waitstart(coin,height);
            iguana_updatewaiting(coin,height+1,100);
        }
    } else printf("processrecv: no recvbits!\n");
    return(retval);
}

int32_t iguana_recvblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *block,struct iguana_msgtx *tx,int32_t numtx,uint8_t *data,int32_t origdatalen)
{
    struct iguana_pending *ptr; int32_t allocsize,checklen,numbits; uint32_t datalen,hdrlen;
    if ( coin->R.recvblocks == 0 || coin->R.recvblocks[block->height] != 0 )
    {
        coin->sleeptime++;
        if ( coin->sleeptime > 10000 )
            coin->sleeptime = 10000;
        if ( 0 && addr != coin->peers.localaddr )
            printf("%s recv duplicate at height.%d sleepmillis %.3f\n",addr->ipaddr,block->height,(double)coin->sleeptime/1000.); // add validation/merging
    }
    else
    {
        coin->sleeptime *= .995;
        if ( coin->sleeptime < 1000 )
            coin->sleeptime = 1000;
        // validate block here
        datalen = origdatalen;
        hdrlen = (1 << 31) | (datalen << 3);
        coin->R.srcdatalen += datalen;
        if ( 0 && (numbits= ramcoder_compress(coin->R.compressed,sizeof(coin->R.compressed),data,datalen,coin->R.histo,bits256_zero)) > 0 )
        {
            memset(coin->R.checkbuf,0,datalen);
            if ( (checklen= ramcoder_decompress(coin->R.checkbuf,sizeof(coin->R.checkbuf),coin->R.compressed,numbits,bits256_zero)) == datalen )
            {
                if ( memcmp(coin->R.checkbuf,data,datalen) == 0 )
                {
                    hdrlen = numbits;
                    data = coin->R.compressed;
                    printf("height.%d datalen.%d -> numbits.%d %d compression ratio %.3f [%.4f]\n",block->height,datalen,numbits,hconv_bitlen(numbits),(double)datalen/hconv_bitlen(numbits),(double)coin->R.srcdatalen/(coin->R.compressedtotal+hconv_bitlen(numbits)+sizeof(hdrlen)));
                    datalen = hconv_bitlen(numbits);
                } else printf("ramcoder data datalen.%d compare error\n",datalen), getchar();
            }
            else printf("ramcoder codec error origdatalen.%d numbits.%d datalen. %d -> %d\n",origdatalen,numbits,datalen,checklen), getchar();
        } //else printf("ramcoder compress error %d -> numbits.%d\n",datalen,numbits), getchar();
        coin->R.compressedtotal += (datalen + sizeof(hdrlen));
        allocsize = (int32_t)(sizeof(*ptr) + datalen + sizeof(hdrlen));
        if ( coin->R.maprecvdata != 0 )
        {
            ptr = iguana_tmpalloc(coin,"recv",&coin->R.RSPACE,allocsize);
            if ( block->height > coin->R.RSPACE.maxheight )
                coin->R.RSPACE.maxheight = block->height;
            ptr->next = (int32_t)((long)iguana_tmpalloc(coin,"recv",&coin->R.RSPACE,0) - (long)ptr);
        }
        else
        {
            ptr = mycalloc('P',1,allocsize);
            coin->R.packetsallocated += allocsize;
        }
        ptr->allocsize = allocsize;
        ptr->datalen = datalen;
        memcpy(ptr->data,&hdrlen,sizeof(hdrlen));
        memcpy(&ptr->data[sizeof(hdrlen)],data,datalen);
        ptr->ipbits = addr != 0 ? addr->ipbits : 0;
        ptr->block = *block;
        ptr->numtx = numtx;
        ptr->origdatalen = origdatalen;
        if ( (rand() % 1000) == 0 )
            printf("%s recv.%d ptr.%p datalen.%d orig.%d %.3f | parsed.%d hwm.%d longest.%d | %d/%d elapsed %.2f\n",addr != 0 ? addr->ipaddr : "local",block->height,ptr,datalen,origdatalen,(double)origdatalen/datalen,coin->blocks.parsedblocks,coin->blocks.hwmheight,coin->longestchain,iguana_updatewaiting(coin,coin->blocks.parsedblocks,coin->width*10),coin->width*10,(double)(time(NULL)-coin->starttime)/60.);
        coin->R.recvblocks[block->height] = ptr;
    }
    return(0);
}*/
