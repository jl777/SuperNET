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


// Todo list:
// q) investigate if rebroadcast reorged local chain notary tx and scanning mempool is needed

#define CHECKSIG 0xac

#include "iguana777.h"
#include "notaries.h"

int32_t dpow_datahandler(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,uint8_t nn_senderind,uint32_t channel,uint32_t height,uint8_t *data,int32_t datalen);
uint64_t dpow_maskmin(uint64_t refmask,struct dpow_block *bp,int8_t *lastkp);
int32_t dpow_checkutxo(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,struct iguana_info *coin,bits256 *txidp,int32_t *voutp,char *coinaddr);

#include "dpow/dpow_network.c"
#include "dpow/dpow_rpc.c"
#include "dpow/dpow_tx.c"
#include "dpow/dpow_fsm.c"
#include "dpow/dpow_prices.c"

void dpow_fifoupdate(struct supernet_info *myinfo,struct dpow_checkpoint *fifo,struct dpow_checkpoint tip)
{
    int32_t i,ind; struct dpow_checkpoint newfifo[DPOW_FIFOSIZE]; 
    memset(newfifo,0,sizeof(newfifo));
    for (i=DPOW_FIFOSIZE-1; i>0; i--)
    {
        if ( (0) && bits256_nonz(fifo[i-1].blockhash.hash) != 0 && (tip.blockhash.height - fifo[i-1].blockhash.height) != i )
            printf("(%d != %d) ",(tip.blockhash.height - fifo[i-1].blockhash.height),i);
        if ( (ind= (tip.blockhash.height - fifo[i-1].blockhash.height)) >= 0 && ind < DPOW_FIFOSIZE )
            newfifo[ind] = fifo[i-1];
    }
    newfifo[0] = tip;
    memcpy(fifo,newfifo,sizeof(newfifo));
    //for (i=0; i<DPOW_FIFOSIZE; i++)
    //    printf("%d ",bits256_nonz(fifo[i].blockhash.hash));
    //printf(" <- fifo %s\n",bits256_str(str,tip.blockhash.hash));
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
    void **ptrs; char str[65]; struct dpow_checkpoint checkpoint; int32_t freq,minsigs; //uint8_t pubkeys[64][33];
    dpow_checkpointset(myinfo,&dp->last,height,hash,timestamp,blocktime);
    checkpoint = dp->srcfifo[dp->srcconfirms];
    if ( strcmp("BTC",dp->dest) == 0 )
    {
        freq = DPOW_CHECKPOINTFREQ;
        minsigs = DPOW_MINSIGS;
    }
    else
    {
        freq = 1;
        //minsigs = 7;//(komodo_notaries(dp->symbol,pubkeys,height) >> 1) + 1;
        //if ( minsigs < DPOW_MINSIGS )
        minsigs = DPOW_MINSIGS;
    }
    printf("%s/%s src ht.%d dest.%u nonz.%d %s minsigs.%d\n",dp->symbol,dp->dest,checkpoint.blockhash.height,dp->destupdated,bits256_nonz(checkpoint.blockhash.hash),bits256_str(str,dp->last.blockhash.hash),minsigs);
    dpow_fifoupdate(myinfo,dp->srcfifo,dp->last);
    if ( dp->SRCREALTIME == 0 && strcmp(dp->dest,"KMD") == 0 )
        return;
    if ( bits256_nonz(checkpoint.blockhash.hash) != 0 && (checkpoint.blockhash.height % freq) == 0 )
    {
        dpow_heightfind(myinfo,dp,checkpoint.blockhash.height + 1000);
        ptrs = calloc(1,sizeof(void *)*5 + sizeof(struct dpow_checkpoint));
        ptrs[0] = (void *)myinfo;
        ptrs[1] = (void *)dp;
        ptrs[2] = (void *)(uint64_t)minsigs;
        ptrs[3] = (void *)DPOW_DURATION;
        ptrs[4] = 0;
        memcpy(&ptrs[5],&checkpoint,sizeof(checkpoint));
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
    dp->destupdated = timestamp;
    dpow_checkpointset(myinfo,&dp->destchaintip,height,hash,timestamp,blocktime);
    dpow_approvedset(myinfo,dp,&dp->destchaintip,dp->desttx,dp->numdesttx);
    dpow_fifoupdate(myinfo,dp->destfifo,dp->destchaintip);
    if ( strcmp(dp->dest,"BTC") == 0 )
    {
        printf("%s destupdate ht.%d\n",dp->dest,height);
        dpow_destconfirm(myinfo,dp,&dp->destfifo[DPOW_BTCCONFIRMS]);
    }
    else dpow_destconfirm(myinfo,dp,&dp->destfifo[DPOW_KOMODOCONFIRMS*2]); // todo: change to notarized KMD depth
}

void iguana_dPoWupdate(struct supernet_info *myinfo,struct dpow_info *dp)
{
    int32_t height,num; uint32_t blocktime; bits256 blockhash; struct iguana_info *src,*dest;
    //fprintf(stderr,"dp.%p dPoWupdate (%s -> %s)\n",dp,dp!=0?dp->symbol:"",dp!=0?dp->dest:"");
    //if ( strcmp(dp->symbol,"KMD") == 0 )
    {
        num = dpow_nanomsg_update(myinfo);
        //fprintf(stderr,"%d ",num);
    }
    src = iguana_coinfind(dp->symbol);
    dest = iguana_coinfind(dp->dest);
    if ( src != 0 && dest != 0 )
    {
        dp->numdesttx = sizeof(dp->desttx)/sizeof(*dp->desttx);
        if ( (height= dpow_getchaintip(myinfo,&blockhash,&blocktime,dp->desttx,&dp->numdesttx,dest)) != dp->destchaintip.blockhash.height && height >= 0 )
        {
            char str[65];
            if ( strcmp(dp->symbol,"KMD") == 0 || height != dp->destchaintip.blockhash.height+1 )
                printf("[%s].%d %s %s height.%d vs last.%d\n",dp->symbol,dp->SRCHEIGHT,dp->dest,bits256_str(str,blockhash),height,dp->destchaintip.blockhash.height);
            if ( height <= dp->destchaintip.blockhash.height )
            {
                printf("iguana_dPoWupdate dest.%s reorg detected %d vs %d\n",dp->dest,height,dp->destchaintip.blockhash.height);
                if ( height == dp->destchaintip.blockhash.height && bits256_cmp(blockhash,dp->destchaintip.blockhash.hash) != 0 )
                    printf("UNEXPECTED ILLEGAL BLOCK in dest chaintip\n");
            } else dpow_destupdate(myinfo,dp,height,blockhash,(uint32_t)time(NULL),blocktime);
        } // else printf("error getchaintip for %s\n",dp->dest);
        dp->numsrctx = sizeof(dp->srctx)/sizeof(*dp->srctx);
        if ( strcmp(dp->dest,"KMD") == 0 && dp->SRCHEIGHT < src->longestchain )
        {
            //fprintf(stderr,"[I ");
            dp->SRCHEIGHT = dpow_issuer_iteration(dp,src,dp->SRCHEIGHT,&dp->SRCREALTIME);
            //fprintf(stderr," %d] ",dp->SRCHEIGHT);
        }
        if ( (height= dpow_getchaintip(myinfo,&blockhash,&blocktime,dp->srctx,&dp->numsrctx,src)) != dp->last.blockhash.height && height >= 0 )
        {
            char str[65]; printf("[%s].%d %s %s height.%d vs last.%d\n",dp->dest,dp->SRCHEIGHT,dp->symbol,bits256_str(str,blockhash),height,dp->last.blockhash.height);
            if ( dp->lastheight == 0 )
                dp->lastheight = height-1;
            if ( height < dp->last.blockhash.height )
            {
                printf("iguana_dPoWupdate src.%s reorg detected %d vs %d approved.%d notarized.%d\n",dp->symbol,height,dp->last.blockhash.height,dp->approved[0].height,dp->notarized[0].height);
                if ( height <= dp->approved[0].height )
                {
                    if ( bits256_cmp(blockhash,dp->last.blockhash.hash) != 0 )
                        printf("UNEXPECTED ILLEGAL BLOCK in src chaintip\n");
                }
                else
                {
                    while ( dp->lastheight <= height )
                    {
                        blockhash = dpow_getblockhash(myinfo,src,dp->lastheight);
                        dpow_srcupdate(myinfo,dp,dp->lastheight++,blockhash,(uint32_t)time(NULL),blocktime);
                    }
                }
            }
            else
            {
                while ( dp->lastheight <= height )
                {
                    blockhash = dpow_getblockhash(myinfo,src,dp->lastheight);
                    dpow_srcupdate(myinfo,dp,dp->lastheight++,blockhash,(uint32_t)time(NULL),blocktime);
                }
            }
        } //else printf("error getchaintip for %s\n",dp->symbol);
    } else printf("iguana_dPoWupdate missing src.(%s) %p or dest.(%s) %p\n",dp->symbol,src,dp->dest,dest);
}

void dpow_addresses()
{
    int32_t i; char coinaddr[64]; uint8_t pubkey[33];
    for (i=0; i<sizeof(Notaries)/sizeof(*Notaries); i++)
    {
        decode_hex(pubkey,33,Notaries[i][1]);
        bitcoin_address(coinaddr,60,pubkey,33);
        printf("%s ",coinaddr);
    }
    printf("Numnotaries.%d\n",i);
}

#include "../includes/iguana_apideclares.h"

TWO_STRINGS(iguana,dpow,symbol,pubkey)
{
    char *retstr,srcaddr[64],destaddr[64]; struct iguana_info *src,*dest; cJSON *ismine; int32_t i,srcvalid,destvalid; struct dpow_info *dp = &myinfo->DPOWS[myinfo->numdpows];
    destvalid = srcvalid = 0;
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
    if ( dp->symbol[0] != 0 )
        return(clonestr("{\"error\":\"cant dPoW more than one coin at a time\"}"));
    if ( pubkey == 0 || pubkey[0] == 0 || is_hexstr(pubkey,0) != 66 )
        return(clonestr("{\"error\":\"need 33 byte pubkey\"}"));
    if ( symbol == 0 || symbol[0] == 0 )
        symbol = "KMD";
    //if ( myinfo->numdpows == 1 )
    //    komodo_assetcoins(-1);
    if ( iguana_coinfind(symbol) == 0 )
        return(clonestr("{\"error\":\"cant dPoW an inactive coin\"}"));
    if ( strcmp(symbol,"KMD") == 0 && iguana_coinfind("BTC") == 0 )
        return(clonestr("{\"error\":\"cant dPoW KMD without BTC\"}"));
    else if ( myinfo->numdpows == 0 && strcmp(symbol,"KMD") != 0 && iguana_coinfind("KMD") == 0 )
        return(clonestr("{\"error\":\"cant dPoW without KMD\"}"));
    if ( myinfo->numdpows > 1 )
    {
        if ( strcmp(symbol,"KMD") == 0 || iguana_coinfind("BTC") == 0 )
        {
            dp->symbol[0] = 0;
            return(clonestr("{\"error\":\"cant dPoW KMD or BTC again\"}"));
        }
        for (i=1; i<myinfo->numdpows; i++)
            if ( strcmp(symbol,myinfo->DPOWS[i].symbol) == 0 )
            {
                dp->symbol[0] = 0;
                return(clonestr("{\"error\":\"cant dPoW same coin again\"}"));
            }
    }
    strcpy(dp->symbol,symbol);
    if ( strcmp(dp->symbol,"KMD") == 0 )
    {
        strcpy(dp->dest,"BTC");
        dp->srcconfirms = DPOW_KOMODOCONFIRMS;
    }
    else
    {
        strcpy(dp->dest,"KMD");
        dp->srcconfirms = DPOW_THIRDPARTY_CONFIRMS;
    }
    if ( dp->srcconfirms > DPOW_FIFOSIZE )
        dp->srcconfirms = DPOW_FIFOSIZE;
    src = iguana_coinfind(dp->symbol);
    dest = iguana_coinfind(dp->dest);
    if ( src == 0 || dest == 0 )
    {
        dp->symbol[0] = 0;
        return(clonestr("{\"error\":\"source coin or dest coin not there\"}"));
    }
    char tmp[67];
    safecopy(tmp,pubkey,sizeof(tmp));
    decode_hex(dp->minerkey33,33,tmp);
    bitcoin_address(srcaddr,src->chain->pubtype,dp->minerkey33,33);
    if ( (retstr= dpow_validateaddress(myinfo,src,srcaddr)) != 0 )
    {
        json = cJSON_Parse(retstr);
        if ( (ismine= jobj(json,"ismine")) != 0 && is_cJSON_True(ismine) != 0 )
            srcvalid = 1;
        else srcvalid = 0;
        free(retstr);
        retstr = 0;
    }
    bitcoin_address(destaddr,dest->chain->pubtype,dp->minerkey33,33);
    if ( (retstr= dpow_validateaddress(myinfo,dest,destaddr)) != 0 )
    {
        json = cJSON_Parse(retstr);
        if ( (ismine= jobj(json,"ismine")) != 0 && is_cJSON_True(ismine) != 0 )
            destvalid = 1;
        else destvalid = 0;
        free(retstr);
        retstr = 0;
    }
    for (i=0; i<33; i++)
        printf("%02x",dp->minerkey33[i]);
    printf(" DPOW with pubkey.(%s) %s.valid%d %s -> %s %s.valid%d\n",tmp,srcaddr,srcvalid,dp->symbol,dp->dest,destaddr,destvalid);
    if ( srcvalid <= 0 || destvalid <= 0 )
    {
        dp->symbol[0] = 0;
        return(clonestr("{\"error\":\"source address or dest address has no privkey, importprivkey\"}"));
    }
    if ( bitcoin_pubkeylen(dp->minerkey33) <= 0 )
    {
        dp->symbol[0] = 0;
        return(clonestr("{\"error\":\"illegal pubkey\"}"));
    }
    if ( dp->blocks == 0 )
    {
        dp->maxblocks = 1000000;
        dp->blocks = calloc(dp->maxblocks,sizeof(*dp->blocks));
    }
    portable_mutex_init(&dp->paxmutex);
    portable_mutex_init(&dp->dexmutex);
    PAX_init();
    //printf(">>>>>>>>>>>>>>> call paxpending\n");
    //uint8_t buf[32768];
    //dpow_paxpending(buf);
    myinfo->numdpows++;
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
    if ( (coin= iguana_coinfind("ZEC")) != 0 )
        return(dpow_passthru(coin,function,hex));
    else return(clonestr("{\"error\":\"ZEC not active, start in bitcoind mode\"}"));
}

TWO_STRINGS(komodo,passthru,function,hex)
{
    if ( (coin= iguana_coinfind("KMD")) != 0 )
        return(dpow_passthru(coin,function,hex));
    else return(clonestr("{\"error\":\"KMD not active, start in bitcoind mode\"}"));
}

THREE_STRINGS(iguana,passthru,asset,function,hex)
{
    if ( asset != 0 && (coin= iguana_coinfind(asset)) != 0 )
        return(dpow_passthru(coin,function,hex));
    else return(clonestr("{\"error\":\"assetchain not active, start in bitcoind mode\"}"));
}


TWO_STRINGS(dex,send,hex,handler)
{
    uint8_t data[8192]; int32_t datalen; char *retstr;
    if ( hex != 0 && (datalen= is_hexstr(hex,0)) > 0 && (datalen>>1) < sizeof(data) )
    {
        datalen >>= 1;
        decode_hex(data,datalen,hex);
        if ( handler == 0 || handler[0] == 0 )
            handler = "DEX";
        if ( (retstr= dex_reqsend(myinfo,handler,data,datalen,1,"")) == 0 )
            return(clonestr("{\"result\":\"success\"}"));
        else return(retstr);
    } else return(clonestr("{\"error\":\"dex send: invalid hex\"}"));
}

STRING_ARG(dpow,pending,fiat)
{
    struct dpow_info *dp; char base[64]; int32_t i;
    if ( fiat != 0 && fiat[0] != 0 )
    {
        for (i=0; fiat[i]!=0; i++)
            base[i] = toupper((int32_t)fiat[i]);
        base[i] = 0;
        for (i=0; i<myinfo->numdpows; i++)
        {
            dp = &myinfo->DPOWS[i];
            if ( strcmp(dp->symbol,base) == 0  )
                return(jprint(dpow_withdraws_pending(dp),1));
        }
    }
    return(clonestr("[]"));
}

STRING_ARG(dpow,bindaddr,ipaddr)
{
    uint32_t ipbits; char checkbuf[64];
    if ( ipaddr != 0 && ipaddr[0] != 0 )
    {
        ipbits = (uint32_t)calc_ipbits(ipaddr);
        expand_ipbits(checkbuf,ipbits);
        if ( strcmp(ipaddr,checkbuf) == 0 )
        {
            strcpy(myinfo->bindaddr,ipaddr);
            return(clonestr("{\"result\":\"success\"}"));
        } else return(clonestr("{\"error\":\"invalid bind ipaddr\"}"));
    } else return(clonestr("{\"error\":\"no bind ipaddr\"}"));
}

STRING_ARG(iguana,addnotary,ipaddr)
{
    static int32_t didinit;
    if ( didinit == 0 )
    {
        dpow_addresses();
        didinit = 1;
    }
    printf("addnotary (%s) -> (%s)\n",ipaddr,myinfo->ipaddr);
    dpow_nanomsginit(myinfo,ipaddr);
    return(clonestr("{\"result\":\"notary node added\"}"));
}

char NOTARY_CURRENCIES[][16] = { "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD",
    "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK",
    "REVS", "SUPERNET", "DEX", "PANGEA", "JUMBLR", "BET", "CRYPTO", "HODL", "SHARK", "BOTS", "MGW", "MVP", "WIRELESS", "KV", "CEAL", "MESH" };

ZERO_ARGS(dpow,notarychains)
{
    int32_t i; cJSON *array = cJSON_CreateArray();
    jaddistr(array,"KMD");
    jaddistr(array,"BTC");
    for (i=0; i<sizeof(NOTARY_CURRENCIES)/sizeof(*NOTARY_CURRENCIES); i++)
        jaddistr(array,NOTARY_CURRENCIES[i]);
    return(jprint(array,1));
}

STRING_AND_INT(dpow,fundnotaries,symbol,numblocks)
{
    int32_t komodo_notaries(char *symbol,uint8_t pubkeys[64][33],int32_t height);
    uint8_t pubkeys[64][33]; cJSON *infojson; char coinaddr[64],cmd[1024]; uint64_t signedmask; int32_t i,j,n,sendflag=0,current=0,height; FILE *fp; double vals[64],sum,val = 0.01;
    if ( (coin= iguana_coinfind("KMD")) == 0 )
        return(clonestr("{\"error\":\"need KMD active\"}"));
    if ( (infojson= dpow_getinfo(myinfo,coin)) != 0 )
    {
        current = jint(infojson,"blocks");
        free_json(infojson);
    } else return(clonestr("{\"error\":\"cant get current height\"}"));
    n = komodo_notaries("KMD",pubkeys,current);
    if ( symbol != 0 && strcmp(symbol,"BTC") == 0 && coin != 0 )
    {
        if ( numblocks == 0 )
            numblocks = 10000;
        //else sendflag = 1;
        memset(vals,0,sizeof(vals));
        if ( (coin= iguana_coinfind("BTC")) != 0 )
        {
            if ( (fp= fopen("signedmasks","rb")) != 0 )
            {
                while ( 1 )
                {
                    if ( fread(&height,1,sizeof(height),fp) == sizeof(height) && fread(&signedmask,1,sizeof(signedmask),fp) == sizeof(signedmask) )
                    {
                        if ( height > current - numblocks )
                        {
                            printf("ht.%d %llx vs current.%d - %d\n",height,(long long)signedmask,current,numblocks);
                            for (j=0; j<64; j++)
                                if ( ((1LL << j) & signedmask) != 0 )
                                    vals[j] += (double)DPOW_UTXOSIZE / SATOSHIDEN;
                        }
                    } else break;
                }
                fclose(fp);
            } else return(clonestr("{\"error\":\"cant open signedmasks\"}"));
            for (sum=j=0; j<n; j++)
            {
                if ( (val= vals[j]) > 0. )
                {
                    bitcoin_address(coinaddr,0,pubkeys[j],33); // fixed
                    sprintf(cmd,"bitcoin-cli sendtoaddress %s %f\n",coinaddr,val);
                    if ( sendflag != 0 && system(cmd) != 0 )
                        printf("ERROR with (%s)\n",cmd);
                    else
                    {
                        printf("%s\n",cmd);
                        sum += val;
                    }
                }
            }
            printf("%s sent %.8f BTC\n",sendflag!=0?"":"would have",sum);
            return(clonestr("{\"result\":\"success\"}"));
        }
        else return(clonestr("{\"error\":\"cant find BTC\"}"));
    }
    for (i=0; i<sizeof(NOTARY_CURRENCIES)/sizeof(*NOTARY_CURRENCIES); i++)
    {
        if ( symbol == 0 || symbol[0] == 0 || strcmp(symbol,NOTARY_CURRENCIES[i]) == 0 )
        {
            if ( symbol != 0 && strcmp(symbol,"KV") == 0 )
                val = 100;
            for (j=0; j<n; j++)
            {
                bitcoin_address(coinaddr,60,pubkeys[j],33);
                sprintf(cmd,"./komodo-cli -ac_name=%s sendtoaddress %s %f",NOTARY_CURRENCIES[i],coinaddr,val);
                if ( system(cmd) != 0 )
                    printf("ERROR with (%s)\n",cmd);
                else printf("%s\n",cmd);
            }
            break;
        }
    }
    return(clonestr("{\"result\":\"success\"}"));
}

STRING_ARG(dpow,active,maskhex)
{
    uint8_t data[8],revdata[8]; int32_t i,len; uint64_t mask; cJSON *retjson,*array = cJSON_CreateArray();
    if ( maskhex == 0 || maskhex[0] == 0 )
    {
        mask = myinfo->DPOWS[0].lastrecvmask;
        for (i=0; i<64; i++)
        {
            if ( ((1LL << i) & mask) != 0 )
            {
                printf("(%d %llx %s) ",i,(long long)(1LL << i),Notaries[i][0]);
                jaddistr(array,Notaries[i][0]);
            }
        }
        retjson = cJSON_CreateObject();
        jadd64bits(retjson,"recvmask",mask);
        jadd(retjson,"notaries",array);
        return(jprint(retjson,1));
    }
    printf("dpow active (%s)\n",maskhex);
    if ( (len= (int32_t)strlen(maskhex)) <= 16 )
    {
        len >>= 1;
        memset(data,0,sizeof(data));
        decode_hex(data,len,maskhex);
        for (i=0; i<len; i++)
            revdata[i] = data[len-1-i];
        mask = 0;
        memcpy(&mask,revdata,sizeof(revdata));
        for (i=0; i<len; i++)
            printf("%02x",data[i]);
        printf(" <- hex mask.%llx\n",(long long)mask);
        for (i=0; i<(len<<3); i++)
            if ( ((1LL << i) & mask) != 0 )
            {
                printf("(%d %llx %s) ",i,(long long)(1LL << i),Notaries[i][0]);
                jaddistr(array,Notaries[i][0]);
            }
        return(jprint(array,1));
    } else return(clonestr("{\"error\":\"maskhex too long\"}"));
}

ZERO_ARGS(dpow,cancelratify)
{
    myinfo->DPOWS[0].cancelratify = 1;
    return(clonestr("{\"result\":\"queued dpow cancel ratify\"}"));
}

TWOINTS_AND_ARRAY(dpow,ratify,minsigs,timestamp,ratified)
{
    void **ptrs; bits256 zero; int32_t i; char *source; struct dpow_checkpoint checkpoint;
    if ( ratified == 0 )
        return(clonestr("{\"error\":\"no ratified list for dpow ratify\"}"));
    memset(zero.bytes,0,sizeof(zero));
    dpow_checkpointset(myinfo,&checkpoint,0,zero,timestamp,timestamp);
    ptrs = calloc(1,sizeof(void *)*5 + sizeof(struct dpow_checkpoint));
    ptrs[0] = (void *)myinfo;
    if ( (source= jstr(json,"source")) == 0 )
        source = "KMD";
    ptrs[1] = (void *)&myinfo->DPOWS[0];
    for (i=0; i<myinfo->numdpows; i++)
        if ( strcmp(myinfo->DPOWS[0].symbol,source) == 0 )
        {
            ptrs[1] = (void *)&myinfo->DPOWS[i];
            break;
        }
    ptrs[2] = (void *)(long)minsigs;
    ptrs[3] = (void *)DPOW_RATIFYDURATION;
    ptrs[4] = (void *)jprint(ratified,0);
    memcpy(&ptrs[5],&checkpoint,sizeof(checkpoint));
    myinfo->DPOWS[0].cancelratify = 0;
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)dpow_statemachinestart,(void *)ptrs) != 0 )
    {
    }
    return(clonestr("{\"result\":\"started ratification\"}"));
}

HASH_AND_STRING(dex,gettransaction,txid,symbol)
{
    return(_dex_getrawtransaction(myinfo,symbol,txid));
}

HASH_AND_STRING_AND_INT(dex,gettxout,txid,symbol,vout)
{
    return(_dex_gettxout(myinfo,symbol,txid,vout));
}

TWO_STRINGS(dex,listunspent,symbol,address)
{
    if ( symbol != 0 && strcmp(symbol,"BTC") == 0 && (coin= iguana_coinfind("BTC")) != 0 && coin->FULLNODE == 0 && myinfo->blocktrail_apikey[0] != 0 )
    {
        char url[1024],*retstr,*coinaddr,*script; int32_t i,n,vout; cJSON *retjson,*data,*item,*item3,*data3; bits256 txid; uint64_t val;
        sprintf(url,"https://api.blocktrail.com/v1/btc/address/%s/unspent-outputs?api_key=%s",address,myinfo->blocktrail_apikey);
        if ( (retstr= issue_curl(url)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                data = jarray(&n,retjson,"data");
                data3 = cJSON_CreateArray();
                //[{"hash":"e0a40dac21103e92e0dc9311a0233640489afc5beb5ba3b009848a8e9151dc55","time":"2017-02-21T16:48:28+0000","confirmations":1,"is_coinbase":false,"value":4100000,"index":1,"address":"19rjYdJtRN3qoammX3r1gxy9bvh8p8DmRc","type":"pubkeyhash","multisig":null,"script":"OP_DUP OP_HASH160 6128e7459989d35d530bcd4066c9aaf1f925430a OP_EQUALVERIFY OP_CHECKSIG","script_hex":"76a9146128e7459989d35d530bcd4066c9aaf1f925430a88ac"}]
                /*{
                    "txid" : "e95d3083baf733dfda2fcd1110fe2937cb3580f8b1b237aad547528440dfa873",
                    "vout" : 1,
                    "address" : "RNgdefRo2iRLWqDXEogJrsTw35MgDPQP4R",
                    "account" : "",
                    "scriptPubKey" : "76a91493088c5f3546225e0ef6ba9c9c6a74d4c2df877388ac",
                    "amount" : 150.00000000,
                    "interest" : 0.30000000,
                    "confirmations" : 20599,
                    "spendable" : true
                }*/
                for (i=0; i<n; i++)
                {
                    item = jitem(data,i);
                    txid = jbits256(item,"hash");
                    vout = jint(item,"index");
                    val = j64bits(item,"value");
                    coinaddr = jstr(item,"address");
                    script = jstr(item,"script_hex");
                    item3 = cJSON_CreateObject();
                    jaddbits256(item3,"txid",txid);
                    jaddnum(item3,"vout",vout);
                    jaddnum(item3,"amount",dstr(val));
                    jaddnum(item3,"value",dstr(val));
                    if ( coinaddr != 0 )
                        jaddstr(item3,"address",coinaddr);
                    if ( script != 0 )
                        jaddstr(item3,"scriptPubKey",script);
                    jaddnum(item3,"confirmations",jint(item,"confirmations"));
                    jadd(item3,"spendable",jtrue());
                    jaddi(data3,item3);
                }
                free(retstr);
                retstr = jprint(data3,1);
                free_json(retjson);
            }
            return(retstr);
        }
    }
    return(_dex_listunspent(myinfo,symbol,address));
}

TWO_STRINGS_AND_TWO_DOUBLES(dex,listtransactions,symbol,address,count,skip)
{
    if ( symbol != 0 && strcmp(symbol,"BTC") == 0 && (coin= iguana_coinfind("BTC")) != 0 && coin->FULLNODE == 0 && myinfo->blocktrail_apikey[0] != 0 )
    {
        char url[1024],*retstr,*retstr2; cJSON *retjson,*retjson2,*retjson3,*data,*data2; int32_t i,n;
        sprintf(url,"https://api.blocktrail.com/v1/btc/address/%s/transactions?api_key=%s",address,myinfo->blocktrail_apikey);
        if ( (retstr= issue_curl(url)) != 0 )
        {
            sprintf(url,"https://api.blocktrail.com/v1/btc/address/%s/unconfirmed-transactions?api_key=%s",address,myinfo->blocktrail_apikey);
            if ( (retstr2= issue_curl(url)) != 0 )
            {
                if ( (retjson= cJSON_Parse(retstr)) != 0 && (retjson2= cJSON_Parse(retstr2)) != 0 )
                {
                    data = jarray(&n,retjson,"data");
                    data2 = jarray(&n,retjson2,"data");
                    retjson3 = jduplicate(data);
                    if ( n > 0 )
                    {
                        for (i=0; i<n; i++)
                            jaddi(retjson3,jduplicate(jitem(data2,i)));
                    }
                    printf("combined (%s) and (%s) -> (%s)\n",retstr,retstr2,jprint(retjson3,0));
                    free(retstr);
                    free(retstr2);
                    free_json(retjson);
                    free_json(retjson2);
                    return(jprint(retjson3,1));
                }
            }
        }
    }
    return(_dex_listtransactions(myinfo,symbol,address,count,skip));
}

STRING_ARG(dex,getinfo,symbol)
{
    return(_dex_getinfo(myinfo,symbol));
}

STRING_ARG(dex,getbestblockhash,symbol)
{
    return(_dex_getbestblockhash(myinfo,symbol));
}

STRING_ARG(dex,alladdresses,symbol)
{
    return(_dex_alladdresses(myinfo,symbol));
}

STRING_AND_INT(dex,getblockhash,symbol,height)
{
    return(_dex_getblockhash(myinfo,symbol,height));
}

HASH_AND_STRING(dex,getblock,hash,symbol)
{
    return(_dex_getblock(myinfo,symbol,hash));
}

TWO_STRINGS(dex,sendrawtransaction,symbol,signedtx)
{
    return(_dex_sendrawtransaction(myinfo,symbol,signedtx));
}

TWO_STRINGS(dex,importaddress,symbol,address)
{
    return(_dex_importaddress(myinfo,symbol,address));
}

TWO_STRINGS(dex,checkaddress,symbol,address)
{
    return(_dex_checkaddress(myinfo,symbol,address));
}

TWO_STRINGS(dex,validateaddress,symbol,address)
{
    return(_dex_validateaddress(myinfo,symbol,address));
}

STRING_ARG(dex,getmessage,argstr)
{
    return(_dex_getmessage(myinfo,argstr));
}

STRING_ARG(dex,psock,argstr)
{
    return(_dex_psock(myinfo,argstr));
}

STRING_ARG(dex,getnotaries,symbol)
{
    return(_dex_getnotaries(myinfo,symbol));
}

TWO_STRINGS(dex,kvsearch,symbol,key)
{
    if ( key == 0 || key[0] == 0 )
        return(clonestr("{\"error\":\"kvsearch parameter error\"}"));
    return(_dex_kvsearch(myinfo,symbol,key));
}

THREE_STRINGS_AND_THREE_INTS(dex,kvupdate,symbol,key,value,flags,unused,unusedb)
{
    // need to have some micropayments between client/server, otherwise receiving server incurs costs
    if ( key == 0 || key[0] == 0 || value == 0 || value[0] == 0 )
        return(clonestr("{\"error\":\"kvupdate parameter error\"}"));
    if ( strcmp(symbol,"KV") == 0 )
    {
        if ( flags > 1 )
            return(clonestr("{\"error\":\"only single duration updates via remote access\"}"));
        else if ( strlen(key) > 64 || strlen(value) > 256 )
            return(clonestr("{\"error\":\"only keylen <=64 and valuesize <= 256 allowed via remote access\"}"));
        else
        {
            //printf("call _dex_kvupdate.(%s) -> (%s) flags.%d\n",key,value,flags);
            return(_dex_kvupdate(myinfo,symbol,key,value,flags));
        }
    } else return(clonestr("{\"error\":\"free updates only on KV chain\"}"));
}

#include "kmd_lookup.h"

TWO_STRINGS(dex,listunspent2,symbol,address)
{
    cJSON *retjson;
    if ( myinfo->DEXEXPLORER != 0 )
    {
        if ( symbol != 0 && address != 0 && (coin= iguana_coinfind(symbol)) != 0 )
        {
            if ( coin != 0 )
                coin->DEXEXPLORER = myinfo->DEXEXPLORER * myinfo->IAMNOTARY * (iguana_isnotarychain(coin->symbol) >= 0);
            if ( strcmp(coin->symbol,"BTC") == 0 || coin->DEXEXPLORER == 0 )
                return(clonestr("[]"));
            if ( (retjson= kmd_listunspent(myinfo,coin,address)) != 0 )
                return(jprint(retjson,1));
        }
    }
    if ( symbol != 0 && address != 0 )
        return(_dex_listunspent2(myinfo,symbol,address));
    else return(clonestr("{\"error\":\"dex listunspent2 null symbol, address or coin\"}"));
}

TWO_STRINGS_AND_TWO_DOUBLES(dex,listtransactions2,symbol,address,count,skip)
{
    cJSON *retjson;
    if ( myinfo->DEXEXPLORER != 0 )
    {
        if ( symbol != 0 && address != 0 && (coin= iguana_coinfind(symbol)) != 0 )
        {
            if ( coin != 0 )
                coin->DEXEXPLORER = myinfo->DEXEXPLORER * myinfo->IAMNOTARY * (iguana_isnotarychain(coin->symbol) >= 0);
            if ( strcmp(coin->symbol,"BTC") == 0 || coin->DEXEXPLORER == 0 )
                return(clonestr("[]"));
            if ( (retjson= kmd_listtransactions(myinfo,coin,address,count,skip)) != 0 )
                return(jprint(retjson,1));
        }
    }
    if ( symbol != 0 && address != 0 )
        return(_dex_listtransactions2(myinfo,symbol,address,count,skip));
    else return(clonestr("{\"error\":\"dex listunspent2 null symbol, address or coin\"}"));
}

HASH_AND_STRING_AND_INT(dex,gettxin,txid,symbol,vout)
{
    if ( myinfo->DEXEXPLORER != 0 )
    {
        if ( symbol != 0 && (coin= iguana_coinfind(symbol)) != 0 && coin->DEXEXPLORER != 0 )
            return(jprint(kmd_gettxin(coin,txid,vout),1));
        if ( coin != 0 )
            coin->DEXEXPLORER = myinfo->DEXEXPLORER * myinfo->IAMNOTARY * (iguana_isnotarychain(coin->symbol) >= 0);
    }
    if ( symbol != 0 )
        return(_dex_gettxin(myinfo,symbol,txid,vout));
    else return(clonestr("{\"error\":\"dex gettxin null symbolor coin\"}"));
}

TWO_STRINGS(dex,listspent,symbol,address)
{
    if ( myinfo->DEXEXPLORER != 0 )
    {
        if ( symbol != 0 && address != 0 && (coin= iguana_coinfind(symbol)) != 0 && coin->DEXEXPLORER != 0 )
            return(jprint(kmd_listspent(myinfo,coin,address),1));
        if ( coin != 0 )
            coin->DEXEXPLORER = myinfo->DEXEXPLORER * myinfo->IAMNOTARY * (iguana_isnotarychain(coin->symbol) >= 0);
    }
    if ( symbol != 0 && address != 0 )
        return(_dex_listspent(myinfo,symbol,address));
    else return(clonestr("{\"error\":\"dex listspent null symbol, address or coin\"}"));
}

TWO_STRINGS(dex,getbalance,symbol,address)
{
    char url[512],*retstr; cJSON *retjson; uint64_t val;
    if ( myinfo->DEXEXPLORER != 0 )
    {
        if ( symbol != 0 && address != 0 && (coin= iguana_coinfind(symbol)) != 0 && coin->DEXEXPLORER != 0 )
            return(jprint(kmd_getbalance(myinfo,coin,address),1));
        if ( coin != 0 )
            coin->DEXEXPLORER = myinfo->DEXEXPLORER * myinfo->IAMNOTARY * (iguana_isnotarychain(coin->symbol) >= 0);
    }
    if ( symbol != 0 && address != 0 )
    {
        if ( strcmp(symbol,"BTC") == 0 && myinfo->blocktrail_apikey[0] != 0 )
        {
            sprintf(url,"https://api.blocktrail.com/v1/btc/address/%s?api_key=%s",address,myinfo->blocktrail_apikey);
            if ( (retstr= issue_curl(url)) != 0 )
            {
                if ( (retjson= cJSON_Parse(retstr)) != 0 )
                {
                    //printf("balance\n");
                    if ( (val= j64bits(retjson,"balance")) != 0 )
                    {
                        jdelete(retjson,"balance");
                        jaddnum(retjson,"balance",dstr(val));
                    }
                    //printf("sent\n");
                    if ( (val= j64bits(retjson,"sent")) != 0 )
                    {
                        jdelete(retjson,"sent");
                        jaddnum(retjson,"sent",dstr(val));
                    }
                    //printf("received\n");
                    if ( (val= j64bits(retjson,"received")) != 0 )
                    {
                        jdelete(retjson,"received");
                        jaddnum(retjson,"received",dstr(val));
                    }
                    //printf("unconfirmed_sent\n");
                    if ( (val= j64bits(retjson,"unconfirmed_sent")) != 0 )
                    {
                        jdelete(retjson,"unconfirmed_sent");
                        jaddnum(retjson,"unconfirmed_sent",dstr(val));
                    }
                    //printf("unconfirmed_received\n");
                    if ( (val= j64bits(retjson,"unconfirmed_received")) != 0 )
                    {
                        jdelete(retjson,"unconfirmed_received");
                        jaddnum(retjson,"unconfirmed_received",dstr(val));
                    }
                    //printf("(%s) -> (%s)\n",retstr,jprint(retjson,0));
                    free(retstr);
                    retstr = jprint(retjson,1);
                }
            }
            return(retstr);
        }
        return(_dex_getbalance(myinfo,symbol,address));
    } else return(clonestr("{\"error\":\"dex getbalance null symbol, address or coin\"}"));
}

STRING_ARG(dex,explorer,symbol)
{
    if ( symbol != 0 && (coin= iguana_coinfind(symbol)) != 0 )
    {
        myinfo->DEXEXPLORER = 1;
        coin->DEXEXPLORER = 1;
        return(clonestr("{\"result\":\"success\"}"));
    }
    return(clonestr("{\"error\":\"coin not active\"}"));
}

#include "../includes/iguana_apiundefs.h"


