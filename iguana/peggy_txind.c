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

#include "peggy.h"

struct opreturn_protocol
{
    uint8_t id[3]; char name[16];
    int64_t (*process)(void *context,int32_t flags,void *fundedcoinaddr,uint64_t fundedvalue,uint8_t *data,int32_t datalen,uint32_t currentblocknum,uint32_t blocktimestamp,uint32_t isstaked);
    int32_t (*emit)(void *context,uint8_t opreturndata[MAX_OPRETURNSIZE],struct opreturn_payment *payments,int32_t max,uint32_t currentblocknum,uint32_t blocknum,uint32_t blocktimestamp);
    int32_t (*flush)(void *context,uint32_t currentblocknum,uint32_t blocknum,uint32_t blocktimestamp);
    int32_t (*init)(struct txinds777_info *opreturns,uint32_t blocknum,uint32_t blocktimestamp,char *path,void *globals[OPRETURNS_CONTEXTS],int32_t lookbacks[OPRETURNS_CONTEXTS],int32_t max);
    uint32_t (*clone)(char *path,void *dest,void *src);
    uint32_t (*currentblock)(void *globals);
    void *(*replay)(char *path,struct txinds777_info *opreturns,void *_PEGS,uint32_t blocknum,char *opreturnstr,uint8_t *data,int32_t datalen);
    void *globals[OPRETURNS_CONTEXTS]; int32_t lookbacks[OPRETURNS_CONTEXTS],numcontexts; uint32_t pastblocknums[OPRETURNS_CONTEXTS];
    struct txinds777_info *opreturns;
} OPRETURN_PROTOCOLS[8] = { { { 'P', 'A', 'X' }, "peggy", peggy_process, peggy_emit, peggy_flush, peggy_init_contexts, peggy_clone, peggy_currentblock, peggy_replay } };

int32_t opreturns_init(uint32_t blocknum,uint32_t blocktimestamp,char *path)
{
    int32_t i;
    for (i=0; i<sizeof(OPRETURN_PROTOCOLS)/sizeof(*OPRETURN_PROTOCOLS); i++)
    {
        if ( OPRETURN_PROTOCOLS[i].init == 0 )
            break;
        else
        {
            OPRETURN_PROTOCOLS[i].opreturns = txinds777_init(path,"opreturns");
            printf("txinds init.%p\n",OPRETURN_PROTOCOLS[i].opreturns);
            (*OPRETURN_PROTOCOLS[i].init)(OPRETURN_PROTOCOLS[i].opreturns,blocknum,blocktimestamp,path,OPRETURN_PROTOCOLS[i].globals,OPRETURN_PROTOCOLS[i].lookbacks,OPRETURNS_CONTEXTS);
        }
    }
    return(i);
}

struct opreturn_protocol *opreturns_find(uint8_t id[3],char *name)
{
    int32_t i;
    for (i=0; i<sizeof(OPRETURN_PROTOCOLS)/sizeof(*OPRETURN_PROTOCOLS); i++)
        if ( (id != 0 && memcmp(OPRETURN_PROTOCOLS[i].id,id,3) == 0) || (name != 0 && strcmp(name,OPRETURN_PROTOCOLS[i].name) == 0) )
            return(&OPRETURN_PROTOCOLS[i]);
    return(0);
}

void *opreturns_context(char *name,int32_t context)
{
    struct opreturn_protocol *protocol;
    if ( (protocol= opreturns_find(0,name)) != 0 )
        return(protocol->globals[context]);
    return(0);
}

int32_t opreturns_process(int32_t flags,uint32_t currentblocknum,uint32_t blocknum,uint32_t blocktimestamp,struct opreturn_entry *list,int32_t num,uint8_t *peggyopreturn,int32_t peggylen)
{
    static uint32_t prevblocknum; struct opreturn_entry stakedblock;
    int32_t i,iter,size,isstaked,lookback,numvalid = 0; uint64_t len; uint32_t pastblocknum; uint8_t buf[16384]; long offset = 1;
    struct opreturn_protocol *protocol; struct opreturn_entry *opreturn = list;
    if ( prevblocknum != 0 && currentblocknum != prevblocknum+1 )
    {
        if ( currentblocknum > prevblocknum+1 )
            printf("skipped block? currentblocknum %u > %u prevblocknum\n",currentblocknum,prevblocknum);
        else
        {
            for (i=0; i<sizeof(OPRETURN_PROTOCOLS)/sizeof(*OPRETURN_PROTOCOLS); i++)
            {
                protocol = &OPRETURN_PROTOCOLS[i];
                (*protocol->clone)("opreturns_PERM",protocol->globals[0],protocol->globals[1]);
                while ( (blocknum= (*protocol->currentblock)(protocol->globals[0])) < currentblocknum )
                    (*protocol->replay)("opreturns",protocol->opreturns,protocol->globals[0],blocknum,0,0,0);
            }
        }
    }
    prevblocknum = blocknum = currentblocknum;
    for (i=0; i<sizeof(OPRETURN_PROTOCOLS)/sizeof(*OPRETURN_PROTOCOLS); i++)
    {
        if ( OPRETURN_PROTOCOLS[i].opreturns != 0 )
        {
            txinds777_flush(OPRETURN_PROTOCOLS[i].opreturns,blocknum,blocktimestamp);
            printf("flush.%p globals.%p %u %u %u\n",OPRETURN_PROTOCOLS[i].flush,OPRETURN_PROTOCOLS[i].globals[0],currentblocknum,blocknum,blocktimestamp);
            if ( OPRETURN_PROTOCOLS[i].flush != 0 )
                (*OPRETURN_PROTOCOLS[i].flush)(OPRETURN_PROTOCOLS[i].globals[0],currentblocknum,blocknum,blocktimestamp);
        }
    }
    for (i=0; i<sizeof(OPRETURN_PROTOCOLS)/sizeof(*OPRETURN_PROTOCOLS); i++)
    {
        protocol = &OPRETURN_PROTOCOLS[i];
        for (iter=1; iter<protocol->numcontexts; iter++)
        {
            lookback = protocol->lookbacks[iter];
            if ( blocknum > lookback )
            {
                pastblocknum = blocknum - lookback;
                while ( protocol->pastblocknums[iter] <= pastblocknum )
                {
                    txinds777_seek(protocol->opreturns,pastblocknum);
                    while ( (opreturn= txinds777_read(&size,buf,protocol->opreturns)) != 0 )
                    {
                        if ( opreturn->blocknum != pastblocknum )
                            break;
                        if ( opreturn->data[0] == OP_RETURN_OPCODE )
                        {
                            offset = hdecode_varint(&len,opreturn->data,offset,sizeof(opreturn->data));
                            if ( len == (opreturn->datalen + offset) && protocol->id[0] == opreturn->data[offset] && protocol->id[1] == opreturn->data[offset+1] && protocol->id[2] == opreturn->data[offset+2] )
                            {
                                if ( (*protocol->process)(protocol->globals[1],flags,opreturn->vout.coinaddr,opreturn->vout.value,&opreturn->data[offset+3],(int32_t)len-3,pastblocknum,opreturn->timestamp,opreturn->isstaked) < 0 )
                                {
                                    printf("process_opreturns[%d]: protocol.%s rejects entry\n",i,protocol->name);
                                }
                            }
                        }
                    }
                    protocol->pastblocknums[iter] = pastblocknum++;
                }
            }
        }
    }
    for (i=0; i<=num; i++)
    {
        isstaked = 0;
        if ( i == 0 )
        {
            if ( peggyopreturn != 0 )
            {
                opreturn = &stakedblock;
                memset(&stakedblock,0,sizeof(stakedblock));
                memcpy(stakedblock.data,peggyopreturn,peggylen);
                stakedblock.datalen = peggylen;
                isstaked = 1;
            } else continue;
        }
        else opreturn = &list[i-1];
        opreturn->isstaked = isstaked;
        if ( opreturn->data[0] == OP_RETURN_OPCODE )
        {
            offset = hdecode_varint(&len,opreturn->data,offset,sizeof(opreturn->data));
            if ( (len + offset) == opreturn->datalen )
            {
                if ( (protocol= opreturns_find(&opreturn->data[offset],0)) != 0 )
                {
                    txind777_create(OPRETURN_PROTOCOLS[i].opreturns,currentblocknum,blocktimestamp,opreturn,(int32_t)(sizeof(*opreturn)-sizeof(opreturn->data) + opreturn->datalen + 8));
                    if ( (*protocol->process)(protocol->globals[0],flags,opreturn->vout.coinaddr,opreturn->vout.value,&opreturn->data[offset+3],(int32_t)len-3,currentblocknum,blocktimestamp,isstaked) < 0 )
                    {
                        printf("process_opreturns[%d]: protocol.%s rejects entry\n",i,protocol->name);
                    }
                    numvalid++;
                }
            } else printf("process_opreturns[%d]: unexpected datalen.%d vs x.%llu at offset.%ld\n",i,opreturn->datalen,(long long)len,offset);
        } else printf("process_opreturns[%d]: unexpected opcode.%d != OP_RETURN %d\n",i,opreturn->data[0],OP_RETURN_OPCODE);
    }
    return(numvalid);
}

int32_t opreturns_emit(char *name,uint8_t opreturndata[MAX_OPRETURNSIZE],struct opreturn_payment *payments,int32_t max,uint32_t currentblocknum,uint32_t blocknum,uint32_t blocktimestamp)
{
    struct opreturn_protocol *protocol;
    if ( (protocol= opreturns_find(0,name)) != 0 )
    {
        if ( payments != 0 && max != 0 )
            memset(payments,0,sizeof(*payments) * max);
        return((*protocol->emit)(protocol->globals[0],opreturndata,payments,max,currentblocknum,blocknum,blocktimestamp));
    }
    printf("opreturns_emit: couldnt find opreturn protocol.(%s)\n",name);
    return(-1);
}

void opreturns_emitloop(char *protocols[],int32_t numprotocols,uint8_t opreturndata[MAX_OPRETURNSIZE],struct opreturn_payment *payments,int32_t max,uint32_t currentblocknum,uint32_t blocknum,uint32_t blocktimestamp)
{
    static int lastopreturni;
    int32_t i,j,opreturnlen;
    for (j=0; j<numprotocols; j++)
    {
        i = (j + lastopreturni + 1) % numprotocols;
        if ( (opreturnlen= opreturns_emit(protocols[i],opreturndata,payments,max,currentblocknum,blocknum,blocktimestamp)) < 0 )
        {
            printf("opreturns_emitloop: error on protocol.(%s)\n",protocols[i]);
            exit(-1);
        }
        if ( opreturnlen > 0 )
        {
            lastopreturni = i;
            opreturndata = 0;
        }
        while ( payments != 0 && max > 0 && payments[0].value != 0 )
            payments++, max--;
        if ( max <= 0 )
            max = 0, payments = 0;
    }
}

int32_t opreturns_queue_payment(queue_t *PaymentsQ,uint32_t blocktimestamp,char *coinaddr,int64_t value)
{
    int32_t len = 0; struct opreturn_payment *item=0,*payment = calloc(1,sizeof(*payment));
    payment->value = value;
    strcpy(payment->coinaddr,coinaddr);
    if ( value < 0 )
    {
        payment->value = -value;
        if ( (item= queue_delete(PaymentsQ,&payment->DL,sizeof(*payment),1)) != 0 )
            free(item);
        else printf("couldnt find queued payment %.8f -> %s t%u\n",dstr(value),coinaddr,blocktimestamp);
        free(payment);
        return(item == 0 ? -1 : 0);
    }
    else queue_enqueue("PaymentsQ",PaymentsQ,&payment->DL,0);
    return(len);
}

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
    sprintf(fname,"%s/%s%s",path,name,suffix), OS_compatible_path(fname);
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
    sprintf(fname,"%s/%s",path,name), OS_compatible_path(fname);
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



