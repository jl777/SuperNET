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


// Todo list:
// a) creation and detection of special transactions to update list of current notaries
// b) updating latest notarized height based on the notarized tx data
// c) prevent overwriting blocks below notarized height
// d) award 5% APR for utxo older than a week when they are spent
// e) round robin mining difficulty
// f) reduce cost for splitting

#define CHECKSIG 0xac

#include "iguana777.h"
#include "notaries.h"

int32_t dpow_datahandler(struct supernet_info *myinfo,uint32_t channel,uint32_t height,uint8_t *data,int32_t datalen);

#include "dpow/dpow_network.c"
#include "dpow/dpow_rpc.c"
#include "dpow/dpow_tx.c"
#include "dpow/dpow_fsm.c"

void dpow_fifoupdate(struct supernet_info *myinfo,struct dpow_checkpoint *fifo,struct dpow_checkpoint tip)
{
    int32_t i,ind; struct dpow_checkpoint newfifo[DPOW_FIFOSIZE]; char str[65];
    memset(newfifo,0,sizeof(newfifo));
    for (i=DPOW_FIFOSIZE-1; i>0; i--)
    {
        if ( bits256_nonz(fifo[i-1].blockhash.hash) != 0 && (tip.blockhash.height - fifo[i-1].blockhash.height) != i )
            printf("(%d != %d) ",(tip.blockhash.height - fifo[i-1].blockhash.height),i);
        if ( (ind= (tip.blockhash.height - fifo[i-1].blockhash.height)) >= 0 && ind < DPOW_FIFOSIZE )
            newfifo[ind] = fifo[i-1];
    }
    newfifo[0] = tip;
    memcpy(fifo,newfifo,sizeof(newfifo));
    for (i=0; i<DPOW_FIFOSIZE; i++)
        printf("%d ",bits256_nonz(fifo[i].blockhash.hash));
    printf(" <- fifo %s\n",bits256_str(str,tip.blockhash.hash));
}

void dpow_checkpointset(struct supernet_info *myinfo,struct dpow_checkpoint *checkpoint,int32_t height,bits256 hash,uint32_t timestamp,uint32_t blocktime)
{
    checkpoint->timestamp = timestamp;
    checkpoint->blocktime = blocktime;
    checkpoint->blockhash.hash = hash;
    checkpoint->blockhash.height = height;
}

void dpow_srcupdate(struct supernet_info *myinfo,struct dpow_info *dp,int32_t height,bits256 hash,uint32_t timestamp,uint32_t blocktime)
{
    void **ptrs; char str[65]; struct dpow_checkpoint checkpoint;
    dpow_checkpointset(myinfo,&dp->last,height,hash,timestamp,blocktime);
    checkpoint = dp->srcfifo[dp->srcconfirms];
    printf("%s srcupdate ht.%d destupdated.%u nonz.%d %s\n",dp->symbol,height,dp->destupdated,bits256_nonz(checkpoint.blockhash.hash),bits256_str(str,dp->last.blockhash.hash));
    dpow_fifoupdate(myinfo,dp->srcfifo,dp->last);
    if ( dp->destupdated != 0 && bits256_nonz(checkpoint.blockhash.hash) != 0 && (checkpoint.blockhash.height % DPOW_CHECKPOINTFREQ) == 0 )
    {
        ptrs = calloc(1,sizeof(void *)*2 + sizeof(struct dpow_checkpoint));
        ptrs[0] = (void *)myinfo;
        ptrs[1] = (void *)dp;
        memcpy(&ptrs[2],&checkpoint,sizeof(checkpoint));
        if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)dpow_statemachinestart,(void *)ptrs) != 0 )
        {
        }
    }
}

void dpow_approvedset(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_checkpoint *checkpoint,bits256 *txs,int32_t numtx)
{
    int32_t i,j; bits256 txid;
    if ( txs != 0 )
    {
        for (i=0; i<numtx; i++)
        {
            txid = txs[i];
            if ( bits256_nonz(txid) != 0 )
            {
                for (j=0; j<DPOW_FIFOSIZE; j++)
                {
                    if ( bits256_cmp(txid,dp->approved[j].hash) == 0 )
                    {
                        if ( bits256_nonz(checkpoint->approved.hash) == 0 || dp->approved[j].height >= checkpoint->approved.height )
                            checkpoint->approved = dp->approved[j];
                    }
                }
            }
        }
    }
}

void dpow_destconfirm(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_checkpoint *checkpoint)
{
    int32_t i;
    if ( bits256_nonz(checkpoint->approved.hash) != 0 )
    {
        for (i=DPOW_FIFOSIZE-1; i>0; i--)
            dp->notarized[i] = dp->notarized[i-1];
        dp->notarized[0] = checkpoint->approved;
    }
}

void dpow_destupdate(struct supernet_info *myinfo,struct dpow_info *dp,int32_t height,bits256 hash,uint32_t timestamp,uint32_t blocktime)
{
    printf("%s destupdate ht.%d\n",dp->dest,height);
    dp->destupdated = timestamp;
    dpow_checkpointset(myinfo,&dp->destchaintip,height,hash,timestamp,blocktime);
    dpow_approvedset(myinfo,dp,&dp->destchaintip,dp->desttx,dp->numdesttx);
    dpow_fifoupdate(myinfo,dp->destfifo,dp->destchaintip);
    if ( strcmp(dp->dest,"BTC") == 0 )
        dpow_destconfirm(myinfo,dp,&dp->destfifo[DPOW_BTCCONFIRMS]);
    else
    {
        dpow_destconfirm(myinfo,dp,&dp->destfifo[DPOW_KOMODOCONFIRMS * 2]); // todo: change to notarized KMD depth
    }
}

void iguana_dPoWupdate(struct supernet_info *myinfo)
{
    int32_t height; char str[65]; uint32_t blocktime; bits256 blockhash; struct iguana_info *src,*dest; struct dpow_info *dp = &myinfo->DPOW;
    dpow_nanomsg_update(myinfo);
    src = iguana_coinfind(dp->symbol);
    dest = iguana_coinfind(dp->dest);
    //printf("dPoWupdate (%s -> %s)\n",dp->symbol,dp->dest);
    if ( src != 0 && dest != 0 )
    {
        dp->numdesttx = sizeof(dp->desttx)/sizeof(*dp->desttx);
        if ( (height= dpow_getchaintip(myinfo,&blockhash,&blocktime,dp->desttx,&dp->numdesttx,dest)) != dp->destchaintip.blockhash.height && height >= 0 )
        {
            printf("%s %s height.%d vs last.%d\n",dp->dest,bits256_str(str,blockhash),height,dp->destchaintip.blockhash.height);
            if ( height <= dp->destchaintip.blockhash.height )
            {
                printf("iguana_dPoWupdate dest.%s reorg detected %d vs %d\n",dp->dest,height,dp->destchaintip.blockhash.height);
                if ( height == dp->destchaintip.blockhash.height && bits256_cmp(blockhash,dp->destchaintip.blockhash.hash) != 0 )
                    printf("UNEXPECTED ILLEGAL BLOCK in dest chaintip\n");
            } else dpow_destupdate(myinfo,dp,height,blockhash,(uint32_t)time(NULL),blocktime);
        } // else printf("error getchaintip for %s\n",dp->dest);
        dp->numsrctx = sizeof(dp->srctx)/sizeof(*dp->srctx);
        if ( (height= dpow_getchaintip(myinfo,&blockhash,&blocktime,dp->srctx,&dp->numsrctx,src)) != dp->last.blockhash.height && height >= 0 )
        {
            printf("%s %s height.%d vs last.%d\n",dp->symbol,bits256_str(str,blockhash),height,dp->last.blockhash.height);
            if ( height < dp->last.blockhash.height )
            {
                printf("iguana_dPoWupdate src.%s reorg detected %d vs %d approved.%d notarized.%d\n",dp->symbol,height,dp->last.blockhash.height,dp->approved[0].height,dp->notarized[0].height);
                if ( height <= dp->approved[0].height )
                {
                    if ( bits256_cmp(blockhash,dp->last.blockhash.hash) != 0 )
                        printf("UNEXPECTED ILLEGAL BLOCK in src chaintip\n");
                } else dpow_srcupdate(myinfo,dp,height,blockhash,(uint32_t)time(NULL),blocktime);
            } else dpow_srcupdate(myinfo,dp,height,blockhash,(uint32_t)time(NULL),blocktime);
        } //else printf("error getchaintip for %s\n",dp->symbol);
    } else printf("iguana_dPoWupdate missing src.(%s) %p or dest.(%s) %p\n",dp->symbol,src,dp->dest,dest);
}

#include "../includes/iguana_apidefs.h"

TWO_STRINGS(iguana,dpow,symbol,pubkey)
{
    char *retstr;
    if ( myinfo->NOTARY.RELAYID < 0 )
    {
        if ( (retstr= basilisk_addrelay_info(myinfo,0,(uint32_t)calc_ipbits(myinfo->ipaddr),myinfo->myaddr.persistent)) != 0 )
        {
            printf("addrelay.(%s)\n",retstr);
            free(retstr);
        }
        if ( myinfo->NOTARY.RELAYID < 0 )
            return(clonestr("{\"error\":\"must be running as notary node\"}"));
    }
    if ( myinfo->DPOW.symbol[0] != 0 )
        return(clonestr("{\"error\":\"cant dPoW more than one coin at a time\"}"));
    if ( pubkey == 0 || pubkey[0] == 0 || is_hexstr(pubkey,0) != 66 )
        return(clonestr("{\"error\":\"need 33 byte pubkey\"}"));
    if ( symbol == 0 || symbol[0] == 0 )
        symbol = "KMD";
    if ( iguana_coinfind(symbol) == 0 )
        return(clonestr("{\"error\":\"cant dPoW an inactive coin\"}"));
    if ( strcmp(symbol,"KMD") == 0 && iguana_coinfind("BTC") == 0 )
        return(clonestr("{\"error\":\"cant dPoW KMD without BTC\"}"));
    else if ( strcmp(symbol,"KMD") != 0 && iguana_coinfind("KMD") == 0 )
        return(clonestr("{\"error\":\"cant dPoW without KMD\"}"));
    decode_hex(myinfo->DPOW.minerkey33,33,pubkey);
    if ( bitcoin_pubkeylen(myinfo->DPOW.minerkey33) <= 0 )
        return(clonestr("{\"error\":\"illegal pubkey\"}"));
    strcpy(myinfo->DPOW.symbol,symbol);
    if ( strcmp(myinfo->DPOW.symbol,"KMD") == 0 )
    {
        strcpy(myinfo->DPOW.dest,"BTC");
        myinfo->DPOW.srcconfirms = DPOW_KOMODOCONFIRMS;
    }
    else
    {
        strcpy(myinfo->DPOW.dest,"KMD");
        myinfo->DPOW.srcconfirms = DPOW_THIRDPARTY_CONFIRMS;
    }
    if ( myinfo->DPOW.srcconfirms > DPOW_FIFOSIZE )
        myinfo->DPOW.srcconfirms = DPOW_FIFOSIZE;
    if ( myinfo->DPOW.blocks == 0 )
        myinfo->DPOW.blocks = calloc(1000000,sizeof(*myinfo->DPOW.blocks));
    return(clonestr("{\"result\":\"success\"}"));
}

char *dpow_passthru(struct iguana_info *coin,char *function,char *hex)
{
    char params[32768]; int32_t len = 0;
    if ( hex != 0 && hex[0] != 0 )
    {
        len = (int32_t)strlen(hex) >> 1;
        if ( len < sizeof(params)-1 )
            decode_hex((uint8_t *)params,(int32_t)strlen(hex),hex);
        else len = 0;
    }
    params[len] = 0;
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,function,params));
}

TWO_STRINGS(zcash,passthru,function,hex)
{
    if ( (coin= iguana_coinfind("ZEC")) != 0 || coin->chain->serverport[0] == 0 )
        return(dpow_passthru(coin,function,hex));
    else return(clonestr("{\"error\":\"ZEC not active, start in bitcoind mode\"}"));
}

TWO_STRINGS(komodo,passthru,function,hex)
{
    if ( (coin= iguana_coinfind("KMD")) != 0 || coin->chain->serverport[0] == 0 )
        return(dpow_passthru(coin,function,hex));
    else return(clonestr("{\"error\":\"KMD not active, start in bitcoind mode\"}"));
}

STRING_ARG(iguana,addnotary,ipaddr)
{
    printf("addnotary (%s) -> (%s)\n",ipaddr,myinfo->ipaddr);
    dpow_nanomsginit(myinfo,ipaddr);
    return(clonestr("{\"result\":\"notary node added\"}"));
}

#include "../includes/iguana_apiundefs.h"


