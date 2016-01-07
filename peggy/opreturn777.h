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
#ifndef opreturn777_h
#define opreturn777_h
// include files
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "../iguana777.h"

#include "txind777.c"

#define OP_RETURN_OPCODE 0x6a
#define OPRETURNS_CONTEXTS 2

// definitions
#define MAX_OPRETURNSIZE 4096
struct opreturn_payment { struct queueitem DL; uint64_t value; char coinaddr[BTCDADDRSIZE]; };
struct opreturn_entry { struct opreturn_payment vout; uint32_t timestamp,blocknum; uint16_t isstaked,txind,v,datalen; uint8_t data[MAX_OPRETURNSIZE]; };

// externs
int32_t opreturns_gotnewblock(uint32_t blocknum,uint32_t blocktimestamp,char *opreturns[],int32_t numopreturns,char *peggybase_opreturnstr);
char *opreturns_stakinginfo(char opreturnstr[8192],uint32_t blocknum,uint32_t blocktimestamp);

int32_t opreturns_process(int32_t flags,uint32_t currentblocknum,uint32_t blocknum,uint32_t blocktimestamp,struct opreturn_entry *list,int32_t num,uint8_t *peggyopreturn,int32_t peggylen);
int32_t opreturns_queue_payment(queue_t *PaymentsQ,uint32_t blocktimestamp,char *coinaddr,int64_t value);
int32_t opreturns_init(uint32_t blocknum,uint32_t blocktimestamp,char *path);
void *opreturns_context(char *name,int32_t context);

int64_t peggy_process(void *context,int32_t flags,void *fundedcoinaddr,uint64_t fundedvalue,uint8_t *data,int32_t datalen,uint32_t currentblocknum,uint32_t blocktimestamp,uint32_t stakedblock);
int32_t peggy_emit(void *context,uint8_t opreturndata[MAX_OPRETURNSIZE],struct opreturn_payment *payments,int32_t max,uint32_t currentblocknum,uint32_t blocknum,uint32_t blocktimestamp);
int32_t peggy_flush(void *context,uint32_t currentblocknum,uint32_t blocknum,uint32_t blocktimestamp);
int32_t peggy_init_contexts(struct txinds777_info *opreturns,uint32_t blocknum,uint32_t blocktimestamp,char *path,void *globals[OPRETURNS_CONTEXTS],int32_t lookbacks[OPRETURNS_CONTEXTS],int32_t maxcontexts);
uint32_t peggy_clone(char *path,void *dest,void *src);
void *peggy_replay(char *path,struct txinds777_info *opreturns,void *_PEGS,uint32_t blocknum,char *opreturnstr,uint8_t *data,int32_t datalen);
uint32_t peggy_currentblock(void *globals);

#endif
#else
#ifndef opreturn777_c
#define opreturn777_c

#ifndef opreturn777_h
#define DEFINES_ONLY
#include "opreturn777.c"
#undef DEFINES_ONLY
#endif

// functions
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
        if ( (item= queue_delete(PaymentsQ,&payment->DL,sizeof(*payment))) != 0 )
            free(item);
        else printf("couldnt find queued payment %.8f -> %s t%u\n",dstr(value),coinaddr,blocktimestamp);
        free(payment);
        return(item == 0 ? -1 : 0);
    }
    else queue_enqueue("PaymentsQ",PaymentsQ,&payment->DL,0);
    return(len);
}

#endif
#endif
