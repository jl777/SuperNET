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

#ifdef DEFINES_ONLY
#ifndef txind777_h
#define txind777_h

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include "../iguana777.h"

#define BTCDADDRSIZE 36


struct txinds777_hdr { int64_t num,nextpos; uint32_t blocknum,timestamp,firstblocknum,lastblocknum; struct sha256_vstate state; bits256 sha256; };
struct txinds777_info
{
    struct txinds777_hdr H;
    FILE *txlogfp,*indexfp,*fp; char path[512],name[64]; int64_t curitem,*blockitems;
};

int64_t txind777_bundle(struct txinds777_info *txinds,uint32_t blocknum,uint32_t timestamp,int64_t *bundle,int32_t numtx);
int64_t txind777_create(struct txinds777_info *txinds,uint32_t blocknum,uint32_t timestamp,void *txdata,uint16_t len);
int32_t txind777_txbuf(uint8_t *txbuf,int32_t len,uint64_t val,int32_t size);
int32_t txinds777_flush(struct txinds777_info *txinds,uint32_t blocknum,uint32_t blocktimestamp);
struct txinds777_info *txinds777_init(char *path,char *name);
int64_t txinds777_seek(struct txinds777_info *txinds,uint32_t blocknum);
void *txinds777_read(int32_t *lenp,uint8_t *buf,struct txinds777_info *txinds);
void txinds777_purge(struct txinds777_info *txinds);

#endif
#else
#ifndef txind777_c
#define txind777_c

#ifndef txind777_h
#define DEFINES_ONLY
#include "txind777.c"
#undef DEFINES_ONLY
#endif

void txinds777_purge(struct txinds777_info *txinds)
{
    if ( txinds->fp != 0 )
        fclose(txinds->fp);
    if ( txinds->txlogfp != 0 )
        fclose(txinds->txlogfp);
    if ( txinds->indexfp != 0 )
        fclose(txinds->indexfp);
    if ( txinds->blockitems != 0 )
        free(txinds->blockitems);
    memset(txinds,0,sizeof(*txinds));
}

int64_t txinds777_seek(struct txinds777_info *txinds,uint32_t blocknum)
{
    if ( txinds->blockitems != 0 && blocknum >= txinds->H.firstblocknum && blocknum <= txinds->H.lastblocknum )
        txinds->curitem = txinds->blockitems[blocknum - txinds->H.firstblocknum];
    else txinds->curitem = 0;
    return(txinds->curitem);
}

void *txinds777_read(int32_t *lenp,uint8_t *buf,struct txinds777_info *txinds)
{
    int64_t txind,fpos; int32_t len; uint32_t triplet[3];
    *lenp = 0;
    if ( txinds->indexfp == 0 || txinds->txlogfp == 0 )
        return(0);
    fseek(txinds->indexfp,txinds->curitem * sizeof(int64_t),SEEK_SET);
    if ( fread(&txind,1,sizeof(txind),txinds->indexfp) != sizeof(txind) )
    {
        printf("error reading txindex.%lld file at pos %lld\n",(long long)txinds->curitem,(long long)(txinds->curitem * sizeof(txind)));
        return(0);
    }
    len = txind & 0xffff;
    fpos = (txind >> 16);
    if ( fpos+len <= txinds->H.nextpos )
    {
        printf("load %ld for item.%d log.%ld\n",ftell(txinds->indexfp),(int32_t)txinds->curitem,(long)fpos);
        fseek(txinds->txlogfp,fpos,SEEK_SET);
        if ( len >= sizeof(triplet) && fread(triplet,1,sizeof(triplet),txinds->txlogfp) == sizeof(triplet) && len > sizeof(triplet) )
        {
            len -= sizeof(triplet);
            if ( fread(buf,1,len,txinds->txlogfp) == len )
            {
                *lenp = len;
                return(buf);
            }
        }
    }
    return(0);
}

void txinds777_ensure(struct txinds777_info *txinds,uint32_t blocknum,uint64_t curitem)
{
    int32_t offset,oldrange,newrange;
    if ( txinds->blockitems == 0 )
    {
        txinds->blockitems = realloc(txinds->blockitems,sizeof(*txinds->blockitems));
        txinds->H.firstblocknum = txinds->H.lastblocknum = blocknum;
    }
    else if ( blocknum > txinds->H.lastblocknum )
    {
        oldrange = (txinds->H.lastblocknum - txinds->H.firstblocknum + 1);
        newrange = (blocknum - txinds->H.firstblocknum + 1);
        txinds->blockitems = realloc(txinds->blockitems,sizeof(*txinds->blockitems) * newrange);
        if ( newrange > oldrange+1 )
            memset(&txinds->blockitems[oldrange],0,(newrange - oldrange));
        txinds->H.lastblocknum = blocknum;
    }
    offset = (blocknum - txinds->H.firstblocknum);
    txinds->blockitems[offset] = curitem;
}

int64_t txind777_create(struct txinds777_info *txinds,uint32_t blocknum,uint32_t timestamp,void *txdata,uint16_t len)
{
    int64_t txind = -1; uint32_t triplet[3];
    if ( txdata == 0 || txinds == 0 )
        return(0);
    if ( len != 0 )
    {
        txind = (txinds->H.nextpos << 16) | (len + sizeof(triplet));
        if ( txinds->txlogfp != 0 )
        {
            triplet[0] = len, triplet[1] = blocknum, triplet[2] = timestamp;
            //printf("triplet.(%d %d %d)\n",len,blocknum,timestamp);
            fseek(txinds->txlogfp,txinds->H.nextpos,SEEK_SET);
            if ( fwrite(triplet,1,sizeof(triplet),txinds->txlogfp) != sizeof(triplet) || fwrite(txdata,1,len,txinds->txlogfp) != len )
            {
                printf("error updating txlog file at pos %lld\n",(long long)txinds->H.nextpos);
                return(-1);
            }
        }
        if ( txinds->indexfp != 0 )
        {
            txinds777_ensure(txinds,blocknum,txinds->H.num);
            fseek(txinds->indexfp,txinds->H.num * sizeof(txind),SEEK_SET);
            if ( fwrite(&txind,1,sizeof(txind),txinds->indexfp) != sizeof(txind) )
            {
                printf("error updating txindex file at pos %lld\n",(long long)(txinds->H.num * sizeof(txind)));
                return(-1);
            }
            txinds->H.num++;
           // printf("H.num %d: indexfp %ld\n",(int32_t)txinds->H.num,ftell(txinds->indexfp));
        }
        vupdate_sha256(txinds->H.sha256.bytes,&txinds->H.state,txdata,len);
        txinds->H.nextpos += len + sizeof(triplet);
        //printf("H.num %d, nextpos %ld (len %ld) indexfp %ld logfp %ld\n",(int32_t)txinds->H.num,(long)txinds->H.nextpos,len + sizeof(triplet),ftell(txinds->indexfp),ftell(txinds->txlogfp));
    } else printf("cant txlog no data\n");
    return(txind);
}

int64_t txind777_bundle(struct txinds777_info *txinds,uint32_t blocknum,uint32_t timestamp,int64_t *bundle,int32_t numtx)
{
    if ( bundle != 0 )
        return(txind777_create(txinds,blocknum,timestamp,bundle,numtx * sizeof(*txinds)));
    else return(0);
}

FILE *txinds777_initfile(long *fposp,char *path,char *name,char *suffix,uint64_t expected)
{
    FILE *fp; char fname[512]; long fpos = 0;
    sprintf(fname,"%s/%s%s",path,name,suffix), iguana_compatible_path(fname);
    if ( (fp= fopen(fname,"rb+")) != 0 )
    {
        fseek(fp,0,SEEK_END);
        if ( (fpos= ftell(fp)) != expected )
        {
            printf("txinds777_init: warning mismatched position %ld vs %lld\n",fpos,(long long)expected);
            fseek(fp,expected,SEEK_SET);
            if ( (fpos= ftell(fp)) != expected )
                printf("txinds777_init: error mismatched position %ld vs %lld after set fpos\n",fpos,(long long)expected);
        }
    }
    else fp = fopen(fname,"wb+");
    *fposp = fpos;
    return(fp);
}

struct txinds777_info *txinds777_init(char *path,char *name)
{
    FILE *fp; char fname[512]; int64_t txind,checktxind; long logfpos,indexfpos; struct txinds777_hdr H,goodH; uint32_t triplet[3];
    struct txinds777_info *txinds = calloc(1,sizeof(*txinds));
    strcpy(txinds->path,path), strcpy(txinds->name,name);
    sprintf(fname,"%s/%s",path,name), iguana_compatible_path(fname);
    printf("txinds777_init(%s,%s)\n",path,name);
    if ( (fp= fopen(fname,"rb+")) != 0 )
    {
        if ( fread(&txinds->H,1,sizeof(txinds->H),fp) == sizeof(txinds->H) )
        {
            txinds->txlogfp = txinds777_initfile(&logfpos,path,name,".log",txinds->H.nextpos);
            txinds->indexfp = txinds777_initfile(&indexfpos,path,name,".index",sizeof(uint64_t) * txinds->H.num);
            if ( txinds->txlogfp != 0 && txinds->indexfp != 0 )
            {
                memset(&goodH,0,sizeof(goodH));
                while ( fread(&H,1,sizeof(H),fp) == sizeof(H) )
                {
                    if ( H.num*sizeof(uint64_t) > indexfpos || H.nextpos > logfpos )
                        break;
                    goodH = H;
                    //printf("loaded H nextpos %d num.%d\n",(int32_t)H.nextpos,(int32_t)H.num);
                }
                txinds->H = goodH;
                if ( txinds->H.nextpos > 0 )
                {
                    txinds->curitem = 0;
                    rewind(txinds->txlogfp);
                    rewind(txinds->indexfp);
                    while ( txinds->curitem < txinds->H.num )
                    {
                        if ( fread(&txind,1,sizeof(txind),txinds->indexfp) != sizeof(txind) )
                            break;
                        logfpos = ftell(txinds->txlogfp);
                        if ( fread(triplet,1,sizeof(triplet),txinds->txlogfp) == sizeof(triplet) )
                        {
                            //printf("triplet.(%d %d %d)\n",triplet[0],triplet[1],triplet[2]);
                            if ( (triplet[0] + logfpos) > txinds->H.nextpos )
                                break;
                            checktxind = (logfpos << 16) | (triplet[0] + sizeof(triplet));
                            if ( checktxind != txind )
                            {
                                printf("checktxind error item.%lld %llx != %llx\n",(long long)txinds->curitem,(long long)checktxind,(long long)txind);
                                txinds->H.num = txinds->curitem;
                                txinds->H.nextpos = logfpos;
                                break;
                            }
                            txinds777_ensure(txinds,triplet[1],txinds->curitem++);
                            fseek(txinds->txlogfp,logfpos + (triplet[0] + sizeof(triplet)),SEEK_SET);
                        }
                    }
                    printf("verified %lld items, curpos %ld %ld\n",(long long)txinds->curitem,ftell(txinds->indexfp),ftell(txinds->txlogfp));
                }
            }
            else
            {
                if ( txinds->txlogfp != 0 )
                    fclose(txinds->txlogfp), txinds->txlogfp = 0;
                if ( txinds->indexfp != 0 )
                    fclose(txinds->indexfp), txinds->indexfp = 0;
            }
        }
        txinds->fp = fp;
    }
    else if ( (txinds->fp= fopen(fname,"wb+")) != 0 )
        fwrite(&txinds->H,1,sizeof(txinds->H),txinds->fp);
    if ( txinds->txlogfp == 0 || txinds->indexfp == 0 )
        vupdate_sha256(txinds->H.sha256.bytes,&txinds->H.state,0,0);
    if ( txinds->txlogfp == 0 )
        txinds->txlogfp = txinds777_initfile(&logfpos,path,name,".log",0);
    if ( txinds->indexfp == 0 )
        txinds->indexfp = txinds777_initfile(&indexfpos,path,name,".index",0);
    //printf("fps %p %p %p\n",txinds->fp,txinds->txlogfp,txinds->indexfp);
    return(txinds);
}

int32_t txind777_txbuf(uint8_t *txbuf,int32_t len,uint64_t val,int32_t size)
{
    int32_t i;
    if ( txbuf != 0 )
        for (i=0; i<size; i++,val>>=8)
            txbuf[len++] = (val & 0xff);
    return(len);
}

int32_t txinds777_flush(struct txinds777_info *txinds,uint32_t blocknum,uint32_t blocktimestamp)
{
    long fpos;
    if ( txinds != 0 )
    {
        if ( txinds->txlogfp != 0 )
            fflush(txinds->txlogfp);
        if ( txinds->indexfp != 0 )
            fflush(txinds->indexfp);
        txinds->H.blocknum = blocknum, txinds->H.timestamp = blocktimestamp;
        if ( txinds->fp != 0 )
        {
            fwrite(&txinds->H,1,sizeof(txinds->H),txinds->fp);
            fpos = ftell(txinds->fp);
            rewind(txinds->fp);
            fwrite(&txinds->H,1,sizeof(txinds->H),txinds->fp);
            fseek(txinds->fp,fpos,SEEK_SET);
            fflush(txinds->fp);
        }
        //printf("txinds777_flush.(%s)\n",txinds->name);
    }
    else
    {
        printf("txinds777_flush null ptr\n");
        //getchar();
    }
    return(0);
}


#endif
#endif


