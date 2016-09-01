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

// included from datachain.c
#include "datachain_KOMODO.c"
#include "datachain_BTC.c"

void datachain_events_process_virt(struct supernet_info *myinfo,struct datachain_info *dPoW,struct datachain_event *event)
{
    
}

int _increasing_events(const void *a,const void *b)
{
#define uint64_a (*(struct datachain_event **)a)->hdrsi_unspentind
#define uint64_b (*(struct datachain_event **)b)->hdrsi_unspentind
	if ( uint64_b > uint64_a )
		return(-1);
	else if ( uint64_b < uint64_a )
		return(1);
	return(0);
#undef uint64_a
#undef uint64_b
}

void datachain_events_sort(struct datachain_info *dPoW)
{
    if ( dPoW->numevents > 0 )
    {
        qsort(dPoW->events,dPoW->numevents,sizeof(dPoW->events),_increasing_events);
        printf("sorted %d events\n",dPoW->numevents);
    }
}

struct datachain_event *datachain_event_create(struct iguana_info *coin,int64_t crypto777_payment,int64_t burned,int32_t height,uint32_t hdrsi,uint32_t unspentind,uint8_t *opreturn,int32_t oplen)
{
    struct datachain_event *event;
    event = calloc(1,sizeof(*event) + oplen);
    event->hdrsi_unspentind = ((uint64_t)hdrsi << 32) | unspentind;
    event->crypto777_payment = crypto777_payment;
    event->burned = burned;
    event->height = height;
    safecopy(event->symbol,coin->symbol,sizeof(event->symbol));
    if ( strcmp(event->symbol,"BTC") == 0 )
        event->btc_or_btcd = DATACHAIN_ISBTC;
    else if ( strcmp(event->symbol,"BTCD") == 0 )
        event->btc_or_btcd = DATACHAIN_ISKOMODO;
    event->oplen = oplen;
    memcpy(event->opreturn,opreturn,oplen);
    return(event);
}

void datachain_events_process(struct supernet_info *myinfo,int32_t btc_or_btcd,struct datachain_info *dPoW,int32_t firsti,int32_t lasti)
{
    int32_t i; struct datachain_event *event;
    if ( firsti >= 0 && lasti <= dPoW->numevents )
    {
        for (i=0; i<=lasti; i++)
            if ( (event= dPoW->events[i]) != 0 )
            {
                if ( btc_or_btcd == DATACHAIN_ISBTC )
                    datachain_events_processBTC(myinfo,dPoW,event);
                else if ( btc_or_btcd == DATACHAIN_ISKOMODO )
                    datachain_events_processKOMODO(myinfo,dPoW,event);
                else datachain_events_process_virt(myinfo,dPoW,event);
                dPoW->state.numprocessed++;
            }
    } else printf("illegal datachain_events_process.[%d, %d] numevents.%d\n",firsti,lasti,dPoW->numevents);
}

void datachain_state_reset(struct supernet_info *myinfo,int32_t btc_or_btcd,struct datachain_info *dPoW)
{
    struct datachain_state *state = &dPoW->state;
    memset(state,0,sizeof(*state));
}

void datachain_reset(struct supernet_info *myinfo,int32_t btc_or_btcd,struct datachain_info *dPoW)
{
    struct iguana_info *virt,*tmp;
    if ( btc_or_btcd == DATACHAIN_ISBTC ) // all needs to be reset on BTC reorg
        datachain_reset(myinfo,DATACHAIN_ISKOMODO,&myinfo->dPoW.BTCD);
    else if ( btc_or_btcd == DATACHAIN_ISKOMODO )
    {
        HASH_ITER(hh,myinfo->allcoins,virt,tmp)
        {
            if ( virt->started != 0 && virt->active != 0 && virt->virtualchain != 0 )
                datachain_reset(myinfo,0,&virt->dPoW);
        }
    }
    datachain_events_sort(dPoW);
    datachain_state_reset(myinfo,btc_or_btcd,dPoW);
}

int32_t datachain_eventadd(struct supernet_info *myinfo,int32_t ordered,struct datachain_info *dPoW,int32_t btc_or_btcd,struct datachain_event *event)
{
    uint64_t hdrsi_unspentind; int32_t retval = 0;
    if ( ordered != 0 )
    {
        if ( dPoW->ordered == 0 )
            datachain_events_sort(dPoW);
    } else dPoW->ordered = 0;
    hdrsi_unspentind = ((uint64_t)dPoW->state.lasthdrsi << 32) | dPoW->state.lastunspentind;
    if ( ordered != 0 )
    {
        if ( dPoW->ordered != dPoW->numevents )
        {
            printf("trigger reset and process.%d ordered.%d numevents.%d\n",btc_or_btcd,dPoW->ordered,dPoW->numevents);
            datachain_reset(myinfo,btc_or_btcd,dPoW);
            if ( dPoW->numevents > 0 )
                datachain_events_process(myinfo,btc_or_btcd,dPoW,0,dPoW->numevents-1);
            if ( btc_or_btcd == DATACHAIN_ISBTC ) // all needs to be reprocessed on BTC reorg
            {
                if ( myinfo->dPoW.BTCD.numevents > 0 )
                    datachain_events_process(myinfo,DATACHAIN_ISKOMODO,&myinfo->dPoW.BTCD,0,myinfo->dPoW.BTCD.numevents - 1);
            }
            else if ( btc_or_btcd == DATACHAIN_ISKOMODO )
            {
                struct iguana_info *virt,*tmp;
                HASH_ITER(hh,myinfo->allcoins,virt,tmp)
                {
                    if ( virt->started != 0 && virt->active != 0 && virt->virtualchain != 0 )
                        if ( virt->dPoW.numevents > 0 )
                            datachain_events_process(myinfo,0,&virt->dPoW,0,virt->dPoW.numevents-1);
                }
            }
            dPoW->ordered = dPoW->numevents;
        }
    }
    if ( event != 0 )
    {
        if ( dPoW->numevents >= dPoW->maxevents )
        {
            dPoW->maxevents += 1024;
            dPoW->events = realloc(dPoW->events,sizeof(*dPoW->events) * dPoW->maxevents);
        }
        if ( event->hdrsi_unspentind > hdrsi_unspentind )
        {
            dPoW->state.lasthdrsi = (uint32_t)(event->hdrsi_unspentind >> 32);
            dPoW->state.lastunspentind = (uint32_t)event->hdrsi_unspentind;
            retval = 1;
        }
        if ( ordered != 0 )
        {
            if ( retval != 1 && dPoW->ordered != 0 )
            {
                printf("datachain_eventadd unexpected ordered event that is not at the end\n");
                retval = -1;
            }
            dPoW->events[dPoW->numevents] = event;
            if ( dPoW->ordered == dPoW->numevents )
                datachain_events_process(myinfo,btc_or_btcd,dPoW,dPoW->numevents,dPoW->numevents);
            dPoW->numevents++;
            dPoW->ordered = dPoW->numevents;
        } else dPoW->events[dPoW->numevents++] = event;
    }
    return(dPoW->numevents);
}

void datachain_update_txidvout(struct supernet_info *myinfo,int32_t ordered,struct iguana_info *coin,struct datachain_info *dPoW,int32_t btc_or_btcd,int32_t spentheight,bits256 txid,int32_t vout,uint8_t rmd160[20],int64_t value)
{
    // MGW via deposit events
}
