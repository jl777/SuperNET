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

/*int32_t basilist_validateblock(cJSON *valsobj)
 {
 uint32_t now,timestamp;
 now = (uint32_t)time(NULL);
 if ( (timestamp= juint(valsobj,"timestamp")) < now-BASILISK_MAXBLOCKLAG || timestamp > now+BASILISK_MAXFUTUREBLOCK )
 return(-1);
 if ( bits256_nonz(prevhash) == 0 )
 prevhash = coin->blocks.hwmchain.RO.hash2;
 if ( (prevblock= iguana_blockfind("setfield",coin,prevhash)) == 0 )
 return(clonestr("{\"error\":\"couldnt find prevhash\"}"));
 if ( (prev2= iguana_blockfind("setfield",coin,prevblock->RO.prev_block)) == 0 )
 return(clonestr("{\"error\":\"couldnt find prevhash2\"}"));
 nonce = juint(valsobj,"nonce");
 nBits = iguana_targetbits(coin,&coin->blocks.hwmchain,prevblock,prev2,1,coin->chain->targetspacing,coin->chain->targettimespan);
 blocktx = basilisk_block(myinfo,coin,&block,1,timestamp,&nonce,prevhash,nBits,prevblock->height+1,0,0,data,datalen,btcdhash,jobj(valsobj,"coinbase"));
 
 return(0);
 }*/

int32_t basilisk_hashstampsfind(struct hashstamp *stamps,int32_t max,struct basilisk_sequence *seq,bits256 hash,uint32_t reftimestamp)
{
    int32_t j,i = 0,foundflag = -1,gap = -1; uint32_t timestamp;
    if ( seq->stamps == 0 )
        return(-1);
    if ( seq->stamps[seq->lasti].timestamp < reftimestamp && seq->lasti >= 3 )
        i = seq->lasti - 3;
    for (; i<seq->numstamps; i++)
    {
        if ( (timestamp= seq->stamps[i].timestamp) == 0 || timestamp > reftimestamp )
        {
            memset(stamps,0,sizeof(*stamps) * max);
            for (j=0; j<max && (i - j)>=0; j++)
                stamps[j] = seq->stamps[i - j];
            return(gap);
        }
        if ( foundflag < 0 && bits256_cmp(hash,seq->stamps[i].hash2) == 0 )
        {
            seq->lasti = i;
            foundflag = i;
            gap = 0;
        }
        else if ( foundflag >= 0 )
            gap++;
    }
    return(-1);
}

bits256 basilisk_hashstampscalc(struct iguana_info *btcd,bits256 *btchashp,uint32_t reftimestamp)
{
    struct hashstamp BTCDstamps[BASILISK_MAXBTCDGAP],BTCstamps[BASILISK_MAXBTCGAP]; bits256 btcdhash;
    btcdhash = *btchashp = GENESIS_PUBKEY;
    if ( basilisk_hashstampsfind(BTCDstamps,BASILISK_MAXBTCDGAP,&btcd->SEQ.BTCD,btcdhash,reftimestamp) < 0 )
    {
        btcdhash = BTCDstamps[BASILISK_MAXBTCDGAP >> 1].hash2;
        if ( basilisk_hashstampsfind(BTCstamps,BASILISK_MAXBTCGAP,&btcd->SEQ.BTC,*btchashp,reftimestamp) < 0 )
            *btchashp = BTCstamps[BASILISK_MAXBTCGAP >> 1].hash2;
    }
    return(btcdhash);
}

// have local coin
int32_t basilisk_hashstampsreverse(struct iguana_info *coin,struct basilisk_sequence *seq,int32_t firstpossible,int32_t max,struct iguana_block *block,uint32_t reftimestamp)
{
    uint32_t timestamp; int32_t j,offset;
    while ( block != 0 && (timestamp= block->RO.timestamp) > reftimestamp )
        block = iguana_blockfind("hashstamps",coin,block->RO.prev_block);
    if ( block == 0 )
        return(-1);
    offset = (block->height - firstpossible);
    for (j=0; j<max; j++,offset--)
    {
        seq->stamps[offset].hash2 = block->RO.hash2;
        seq->stamps[offset].timestamp = block->RO.timestamp;
        seq->stamps[offset].height = block->height;
        if ( offset-- < 0 || (block= iguana_blockfind("revstamp",coin,block->RO.prev_block)) == 0 )
            return(block == 0 ? -1 : j);
    }
    return(j);
}

int32_t basilisk_hashstampset(struct iguana_info *coin,struct hashstamp *stamp,int32_t height)
{
    struct iguana_block *block; struct iguana_bundle *bp;
    if ( height >= 0 && height < coin->bundlescount && (bp= coin->bundles[height / coin->chain->bundlesize]) != 0 )
    {
        if ( (block= bp->blocks[height % coin->chain->bundlesize]) != 0 )
        {
            stamp->hash2 = block->RO.hash2;
            stamp->timestamp = block->RO.timestamp;
            stamp->height = block->height;
            return(0);
        }
    }
    return(-1);
}

void basilisk_ensure(struct basilisk_sequence *seq,int32_t num)
{
    int32_t oldmax,incr = 1000;
    if ( num >= seq->maxstamps )
    {
        oldmax = seq->maxstamps;
        seq->maxstamps = ((num + 2*incr) / incr) * incr;
        seq->stamps = realloc(seq->stamps,sizeof(*seq->stamps) * seq->maxstamps);
        memset(&seq->stamps[oldmax],0,sizeof(*seq->stamps) * (seq->maxstamps - oldmax));
    }
}

int32_t basilisk_hashstampsupdate(struct iguana_info *coin,struct basilisk_sequence *seq,int32_t firstpossible)
{
    while ( (firstpossible + seq->numstamps) < coin->blocks.hwmchain.height )
    {
        basilisk_ensure(seq,seq->numstamps);
        if ( basilisk_hashstampset(coin,&seq->stamps[seq->numstamps],firstpossible + seq->numstamps) < 0 )
            break;
        else seq->numstamps++;
    }
    seq->longestchain = coin->longestchain;
    return(seq->numstamps);
}

int32_t basilisk_update(char *symbol,uint32_t reftimestamp)
{
    struct basilisk_sequence *seq=0; int32_t max=0,firstpossible=0; struct iguana_info *coin; struct iguana_block *block;
    if ( (coin= iguana_coinfind(symbol)) != 0 && (coin->RELAYNODE != 0 || coin->VALIDATENODE != 0) )
    {
        if ( strcmp(symbol,"BTCD") == 0 )
        {
            seq = &coin->SEQ.BTCD;
            firstpossible = BASILISK_FIRSTPOSSIBLEBTCD;
        }
        else if ( strcmp(symbol,"BTC") == 0 )
        {
            seq = &coin->SEQ.BTC;
            firstpossible = BASILISK_FIRSTPOSSIBLEBTC;
        } else return(-1);
        //printf("basilisk update.%s %u lag.%d\n",symbol,reftimestamp,(uint32_t)time(NULL)-seq->lastupdate);
        if ( basilisk_hashstampsupdate(coin,seq,firstpossible) > 0 )
        {
            if ( (block= iguana_blockfind("SEQupdate",coin,coin->blocks.hwmchain.RO.hash2)) != 0 )
                basilisk_hashstampsreverse(coin,seq,firstpossible,max,block,reftimestamp);
            return(0);
        }
    }
    return(-1);
}

int32_t iguana_rwhashstamp(int32_t rwflag,uint8_t zcash,uint8_t *serialized,struct hashstamp *stamp)
{
    int32_t len = 0;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(stamp->hash2),stamp->hash2.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(stamp->timestamp),&stamp->timestamp);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(stamp->height),&stamp->height);
    //len += iguana_rwblockhdr(rwflag,zcash,&serialized[len],(void *)stamp->RO);
    return(len);
}

cJSON *basilisk_sequencejson(uint8_t zcash,struct basilisk_sequence *seq,int32_t startheight,int32_t firstpossible)
{
    int32_t i,n,len=0,datalen,num = 0; cJSON *item; uint8_t *data; char strbuf[8192],*hexstr=0;
    if ( startheight < firstpossible )
        startheight = firstpossible;
    if ( (i= (startheight - firstpossible) ) < 0 || i >= seq->numstamps )
        return(0);
    item = cJSON_CreateObject();
    n = (seq->numstamps - i);
    datalen = (int32_t)(n * sizeof(*seq->stamps));
    data = calloc(n,sizeof(*seq->stamps));
    for (; i<seq->numstamps && num<n; i++,num++)
    {
        if ( seq->stamps[i].timestamp == 0 )
            break;
        len += iguana_rwhashstamp(1,zcash,&data[len],&seq->stamps[i]);
    }
    jaddnum(item,"start",startheight);
    jaddnum(item,"num",num);
    jaddnum(item,"lastupdate",seq->lastupdate);
    jaddnum(item,"longest",seq->longestchain);
    basilisk_addhexstr(&hexstr,item,strbuf,sizeof(strbuf),data,datalen);
    if ( hexstr != 0 )
        free(hexstr);
    return(item);
}

void basilisk_seqresult(struct supernet_info *myinfo,char *retstr)
{
    struct iguana_info *btcd; struct hashstamp stamp; struct basilisk_sequence *seq = 0; cJSON *resultjson; uint8_t *allocptr = 0,space[8192],*data = 0; int32_t ind,startheight,datalen,lastupdate,longestchain,i,num,firstpossible,len = 0; char *hexstr;
    if ( (btcd= iguana_coinfind("BTCD")) != 0 && (resultjson= cJSON_Parse(retstr)) != 0 )
    {
        if ( jstr(resultjson,"BTCD") != 0 )
            seq = &btcd->SEQ.BTCD, firstpossible = BASILISK_FIRSTPOSSIBLEBTCD;
        else if ( jstr(resultjson,"BTC") != 0 )
            seq = &btcd->SEQ.BTC, firstpossible = BASILISK_FIRSTPOSSIBLEBTC;
        if ( seq != 0 )
        {
            startheight = jint(resultjson,"start");
            if ( (ind= startheight-firstpossible) < 0 )
            {
                free_json(resultjson);
                return;
            }
            num = jint(resultjson,"num");
            lastupdate = jint(resultjson,"lastupdate");
            longestchain = jint(resultjson,"longest");
            hexstr = jstr(resultjson,"data");
            printf("got startheight.%d num.%d lastupdate.%d longest.%d (%s)\n",startheight,num,lastupdate,longestchain,hexstr!=0?hexstr:"");
            if ( hexstr != 0 && (data= get_dataptr(&allocptr,&datalen,space,sizeof(space),hexstr)) != 0 )
            {
                basilisk_ensure(seq,ind + num);
                for (i=0; i<num; i++,ind++)
                {
                    len += iguana_rwhashstamp(0,btcd->chain->zcash,&data[len],&stamp);
                    // verify blockheader
                    seq->stamps[ind] = stamp;
                }
            }
            if ( allocptr != 0 )
                free(allocptr);
        }
        free_json(resultjson);
    }
}

char *basilisk_respond_hashstamps(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk)
{
    int32_t startheight; struct iguana_info *btcd; cJSON *retjson = cJSON_CreateObject();
    if ( (btcd= iguana_coinfind("BTCD")) != 0 )
    {
        if ( (startheight= juint(valsobj,"BTCD")) != 0 )
            jadd(retjson,"BTCD",basilisk_sequencejson(btcd->chain->zcash,&btcd->SEQ.BTCD,startheight,BASILISK_FIRSTPOSSIBLEBTCD));
        else if ( (startheight= juint(valsobj,"BTC")) != 0 )
            jadd(retjson,"BTC",basilisk_sequencejson(btcd->chain->zcash,&btcd->SEQ.BTC,startheight,BASILISK_FIRSTPOSSIBLEBTC));
    }
    return(jprint(retjson,1));
}

char *basilisk_coinbase(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,uint8_t *data,int32_t datalen,bits256 coinbasespend,cJSON *origtxjson)
{
    char *rawtx; struct vin_info V; cJSON *txjson;
    if ( (txjson= origtxjson) == 0 )
        txjson = bitcoin_txcreate(1,0);
    bitcoin_txinput(coin,txjson,coinbasespend,-1,0xffffffff,0,0,data,datalen,0,0);
    rawtx = bitcoin_json2hex(myinfo,coin,txidp,txjson,&V);
    if ( txjson != origtxjson )
        free_json(txjson);
    return(rawtx);
}

cJSON *basilisk_paymentsobj(cJSON *txjson,cJSON *valsobj)
{
    cJSON *item,*array; char *coinaddr; uint64_t satoshis; uint8_t addrtype,rmd160[20],outputscript[512]; int32_t i,n,scriptlen;
    if ( txjson == 0 )
        txjson = bitcoin_txcreate(1,juint(valsobj,"locktime"));
    if ( (array= jarray(&n,valsobj,"payments")) != 0 && n > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( (coinaddr= jfieldname(item)) != 0 && (satoshis= j64bits(item,coinaddr)) > 0 )
            {
                bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
                scriptlen = bitcoin_standardspend(outputscript,0,rmd160);
                bitcoin_txoutput(txjson,outputscript,scriptlen,satoshis);
            }
        }
    }
    return(txjson);
}

struct iguana_info *basilisk_chain(struct supernet_info *myinfo,char chainname[BASILISK_MAXNAMELEN],cJSON *valsobj)
{
    char *chainstr,*keystr; bits256 keyhash,chainhash; struct private_chain *chain;
    if ( (chainstr= jstr(valsobj,"chain")) == 0 )
        return(0);
    if ( (keystr= jstr(valsobj,"key")) != 0 )
        vcalc_sha256(0,keyhash.bytes,(uint8_t *)keystr,(int32_t)strlen(keystr));
    else keyhash = GENESIS_PUBKEY;
    vcalc_sha256(0,chainhash.bytes,(uint8_t *)chainstr,(int32_t)strlen(chainstr));
    if ( (chain= category_subscribe(myinfo,chainhash,keyhash)) == 0 )
        return(0);
    safecopy(chainname,chainstr,30), chainname[30] = 0;
    if ( keystr != 0 )
    {
        strcat(chainname,".");
        safecopy(chainname+strlen(chainname),keystr,BASILISK_MAXNAMELEN-1-strlen(chainname));
    }
    return(chain->info);
}

int32_t basilisk_privatechainvals(struct supernet_info *myinfo,char *CMD,cJSON *valsobj)
{
    struct iguana_info *virt; bits256 hash,prevhash; struct iguana_block *block; char chainname[BASILISK_MAXNAMELEN];
    if ( strcmp(CMD,"SET") == 0 || strcmp(CMD,"GET") == 0 )
    {
        if ( (virt= basilisk_chain(myinfo,chainname,valsobj)) == 0 )
            clonestr("{\"error\":\"cant find private chain\"}");
        if ( strcmp(CMD,"SET") == 0 )
        {
            hash = GENESIS_PUBKEY;
            if ( jobj(valsobj,"prev") != 0 )
            {
                prevhash = jbits256(valsobj,"prev");
                if ( (block= iguana_blockfind("basilisk",virt,prevhash)) == 0 )
                {
                    char str[65]; printf("warning couldnt find %s in %s\n",bits256_str(str,prevhash),chainname);
                    prevhash = virt->blocks.hwmchain.RO.hash2;
                }
            } else prevhash = virt->blocks.hwmchain.RO.hash2;
            hash = prevhash;
            if ( jobj(valsobj,"prev") != 0 )
                jdelete(valsobj,"prev");
        }
        return(0);
    }
    return(-1);
}

char *basilisk_block(struct supernet_info *myinfo,struct iguana_info *virt,struct iguana_block *block,int32_t version,uint32_t timestamp,uint32_t *noncep,bits256 prevblock,uint32_t nBits,int32_t height,char **txptrs,int32_t txn_count,uint8_t *coinbase,int32_t coinbaselen,bits256 coinbasespend,cJSON *txjson)
{
    struct iguana_info *btcd; uint8_t serialized[sizeof(*block)],space[16384],*txdata,*allocptr = 0; int32_t i,n,totaltxlen=0,txlen,numiters=1000000; char *coinbasestr,*blockstr=0; bits256 *txids=0,txspace[256],threshold;
    if ( (btcd= iguana_coinfind("BTCD")) == 0 )
    {
        printf("basilisk needs BTCD\n");
        return(0);
    }
    if ( txn_count+2 < sizeof(space)/sizeof(*space) )
    {
        txids = txspace;
        memset(txids,0,sizeof(*txids) * (txn_count+2));
    } else txids = calloc(txn_count+2,sizeof(*txids));
    if ( txn_count > 0 )
    {
        for (i=0; i<txn_count; i++)
        {
            if ( (txdata= get_dataptr(&allocptr,&txlen,space,sizeof(space),txptrs[i])) == 0 )
            {
                printf("basilisk_block error tx.%d\n",i);
                if ( txids != txspace )
                    free(txids);
                return(0);
            }
            totaltxlen += txlen;
            txids[i+1] = bits256_doublesha256(0,txdata,txlen);
            if ( allocptr != 0 )
                free(allocptr);
        }
    }
    if ( (coinbasestr= basilisk_coinbase(myinfo,virt,&txids[0],coinbase,coinbaselen,coinbasespend,txjson)) != 0 )
    {
        memset(block,0,sizeof(*block));
        block->RO.version = version;
        block->RO.prev_block = prevblock;
        block->RO.merkle_root = iguana_merkle(txids,txn_count + 1);
        block->RO.timestamp = timestamp;
        block->RO.bits = nBits;
        block->RO.txn_count = (txn_count + 1);
        block->height = height;
        threshold = bits256_from_compact(nBits);
        //offset = (int32_t)((long)&block->RO.bits - (long)block);
        //n = iguana_serialize_block(virt->chain,&block->RO.hash2,serialized,block);
        if ( (block->RO.nonce= *noncep) == 0 )
        {
            for (i=0; i<numiters; i++)
            {
                block->RO.nonce = rand();
                n = iguana_serialize_block(virt->chain,&block->RO.hash2,serialized,block);
                //char str[65]; printf("nonce.%08x %s\n",block->RO.nonce,bits256_str(str,block->RO.hash2));
                if ( bits256_cmp(threshold,block->RO.hash2) > 0 )
                    break;
            }
        }
        *noncep = block->RO.nonce;
        n = iguana_serialize_block(virt->chain,&block->RO.hash2,serialized,block);
        if ( bits256_cmp(threshold,block->RO.hash2) > 0 )
        {
            blockstr = calloc(1,strlen(coinbasestr) + (totaltxlen+n)*2 + 1);
            init_hexbytes_noT(blockstr,serialized,n);
            strcat(blockstr,coinbasestr);
            for (i=0; i<txn_count; i++)
                strcat(blockstr,txptrs[i]);
        }
        free(coinbasestr);
/*
        if ( (block->RO.nonce= *noncep) == 0 )
        {
            for (i=0; i<numiters; i++)
            {
                block->RO.nonce = rand();
                iguana_rwnum(1,&serialized[offset],sizeof(block->RO.nonce),&block->RO.nonce);
                block->RO.hash2 = iguana_calcblockhash(virt->symbol,virt->chain->hashalgo,serialized,sizeof(struct iguana_msgblockhdr));
                char str[65]; printf("nonce.%08x %s\n",block->RO.nonce,bits256_str(str,block->RO.hash2));
                if ( bits256_cmp(threshold,block->RO.hash2) > 0 )
                {
                    printf("found kernel\n");
                    break;
                }
            }
        }
        *noncep = block->RO.nonce;
        n = iguana_serialize_block(virt->chain,&block->RO.hash2,serialized,block);
        if ( bits256_cmp(threshold,block->RO.hash2) > 0 )
        {
            blockstr = calloc(1,strlen(coinbasestr) + (totaltxlen+n)*2 + 1);
            init_hexbytes_noT(blockstr,serialized,n);
            strcat(blockstr,coinbasestr);
            for (i=0; i<txn_count; i++)
                strcat(blockstr,txptrs[i]);
        } else printf("nonce failure\n");
        free(coinbasestr);*/
    }
    if ( txids != txspace )
        free(txids);
    return(blockstr);
}

int32_t basilisk_blocknonce_verify(struct iguana_info *virt,uint8_t *serialized,int32_t datalen,uint32_t nBits)
{
    bits256 threshold,hash2;
    threshold = bits256_from_compact(nBits);
    hash2 = iguana_calcblockhash(virt->symbol,virt->chain->hashalgo,serialized,datalen);
    if ( bits256_cmp(threshold,hash2) > 0 )
        return(0);
    else return(0);
}

char *basilisk_respond_setfield(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk)
{
    struct iguana_info *virt; struct iguana_block *prevblock,*prev2,*newblock,block; char chainname[BASILISK_MAXNAMELEN],str[65],*blocktx; uint32_t nBits,timestamp,nonce; cJSON *retjson; bits256 btcdhash;
    if ( datalen <= 0 )
        return(clonestr("{\"error\":\"no data specified\"}"));
    if ( (virt= basilisk_chain(myinfo,chainname,valsobj)) == 0 )
        return(clonestr("{\"error\":\"couldnt get basilisk_chain\"}"));
    printf("from.(%s) SET.(%s) datalen.%d prev.%s\n",remoteaddr,jprint(valsobj,0),datalen,bits256_str(str,prevhash));
    if ( bits256_nonz(prevhash) == 0 )
        prevhash = virt->blocks.hwmchain.RO.hash2;
    if ( (prevblock= iguana_blockfind("setfield",virt,prevhash)) == 0 )
        return(clonestr("{\"error\":\"couldnt find prevhash\"}"));
    if ( (prev2= iguana_blockfind("setfield",virt,prevblock->RO.prev_block)) == 0 )
        return(clonestr("{\"error\":\"couldnt find prevhash2\"}"));
    timestamp = juint(valsobj,"timestamp");
    nonce = juint(valsobj,"nonce");
    nBits = iguana_targetbits(virt,(struct iguana_block *)&virt->blocks.hwmchain,prevblock,prev2,1,virt->chain->targetspacing,virt->chain->targettimespan);
    blocktx = basilisk_block(myinfo,virt,&block,1,timestamp,&nonce,prevhash,nBits,prevblock->height+1,0,0,data,datalen,btcdhash,jobj(valsobj,"coinbase"));
    retjson = cJSON_CreateObject();
    jaddbits256(retjson,"hash",block.RO.hash2);
    jaddstr(retjson,"data",blocktx);
    if ( (newblock= _iguana_chainlink(virt,&block)) != 0 )
    {
        jaddstr(retjson,"result","chain extended");
        jaddnum(retjson,"ht",block.height);
    } else jaddstr(retjson,"error","couldnt extend chain");
    free(blocktx);
    return(jprint(retjson,1));
}

char *basilisk_respond_getfield(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk)
{
    struct iguana_info *coin; cJSON *retjson; char chainname[BASILISK_MAXNAMELEN];
    if ( (coin= basilisk_chain(myinfo,chainname,valsobj)) == 0 )
        return(clonestr("{\"error\":\"couldnt get basilisk_chain\"}"));
    printf("getfield\n");
    retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

cJSON *basilisk_genesisjson(struct supernet_info *myinfo,struct iguana_info *btcd,char *chainname,cJSON *valsobj)
{
    char str2[64],hashstr[64],argbuf[1024],*nbitstr,*blockstr; bits256 btchash,btcdhash,zero; uint8_t coinbase[512],buf[4]; int32_t i,coinbaselen; uint32_t nonce,nbits; struct iguana_block genesis; uint32_t timestamp; cJSON *txjson;
    timestamp = (uint32_t)time(NULL);
    btcdhash = basilisk_hashstampscalc(btcd,(bits256 *)coinbase,timestamp);
    if ( bits256_cmp(btcdhash,GENESIS_PUBKEY) == 0 || bits256_cmp(*(bits256 *)coinbase,GENESIS_PUBKEY) == 0 )
    {
        printf("no hashstamps\n");
        return(cJSON_Parse("{\"error\":\"no up to date hashstamps\"}"));
    }
    coinbaselen = (int32_t)strlen(chainname);
    memcpy(&coinbase[sizeof(btchash)],chainname,coinbaselen);
    memset(zero.bytes,0,sizeof(zero));
    nonce = 0;
    if ( (nbitstr= jstr(valsobj,"nbits")) == 0 )
    {
        nbits = BASILISK_DEFAULTDIFF;
        nbitstr = BASILISK_DEFAULTDIFFSTR;
    }
    else
    {
        for (i=0; i<4; i++)
            decode_hex(&buf[3-i],1,&nbitstr[i*2]);
        memcpy(&nbits,buf,sizeof(nbits));
    }
    txjson = basilisk_paymentsobj(0,jobj(valsobj,"payments"));
    blockstr = basilisk_block(myinfo,btcd,&genesis,BASILISK_DEFAULTVERSION,timestamp,&nonce,zero,nbits,0,0,0,coinbase,coinbaselen,btcdhash,txjson);
    bits256_str(hashstr,genesis.RO.hash2);
    sprintf(argbuf,"{\"name\":\"%s\",\"unitval\":%02x,\"genesishash\":\"%s\",\"genesis\":{\"version\":1,\"timestamp\":%u,\"nbits\":\"%s\",\"nonce\":%d,\"merkle_root\":\"%s\"},\"genesisblock\":\"%s\"}",chainname,(nbits >> 24) & 0xff,hashstr,timestamp,nbitstr,genesis.RO.nonce,bits256_str(str2,genesis.RO.merkle_root),blockstr);
    free(blockstr);
    //printf("argbuf.(%s) hash.%s\n",argbuf,hashstr);
    return(cJSON_Parse(argbuf));
}

struct iguana_info *basilisk_privatechain(struct supernet_info *myinfo,char *symbol,char *chainname,cJSON *valsobj)
{
    int32_t datalen,maxpeers,initialheight,minconfirms,maxrequests,maxbundles,hdrsize; int64_t maxrecvcache; uint64_t services; struct iguana_info *virt=0; char *hexstr; uint8_t hexbuf[1024],*ptr,*serialized;
    if ( (hexstr= jstr(valsobj,"genesisblock")) != 0 && (virt= iguana_coinadd(symbol,valsobj)) == 0 )
    {
        safecopy(virt->name,chainname,sizeof(virt->name));
        virt->chain = calloc(1,sizeof(*virt->chain));
        virt->chain->hashalgo = blockhash_sha256;
        serialized = get_dataptr(&ptr,&datalen,hexbuf,sizeof(hexbuf),hexstr);
        iguana_chaininit(virt->chain,1,valsobj);
        iguana_coinargs(symbol,&maxrecvcache,&minconfirms,&maxpeers,&initialheight,&services,&maxrequests,&maxbundles,valsobj);
        iguana_setcoin(myinfo,symbol,virt,maxpeers,maxrecvcache,services,initialheight,0,minconfirms,maxrequests,maxbundles,valsobj);
        hdrsize = (virt->chain->zcash != 0) ? sizeof(struct iguana_msgblockhdr_zcash) : sizeof(struct iguana_msgblockhdr);
        if ( basilisk_blocknonce_verify(virt,serialized,hdrsize,virt->chain->nBits) == 0 )
        {
            virt->chain->genesishash2 = iguana_calcblockhash(symbol,virt->chain->hashalgo,serialized,hdrsize);
            memcpy(virt->chain->genesis_hashdata,virt->chain->genesishash2.bytes,sizeof(virt->chain->genesishash2));
            if ( ptr != 0 )
                free(ptr);
            virt->chain->genesis_hex = clonestr(hexstr);
            virt->MAXPEERS = 0;
            iguana_callcoinstart(virt);
            printf("nonce verified\n");
        } else printf("error validating nonce\n");
    }
    return(virt);
}

cJSON *basilisk_genesisargs(char *symbol,char *chainname,char *chain,char *keystr,char *genesishash,char *genesisblock,char *magicstr,uint16_t port,uint16_t blocktime,char *nbitstr)
{
    int32_t timespan,targetspacing; cJSON *argvals = cJSON_CreateObject();
    if ( genesishash != 0 && genesishash[0] != 0 )
        jaddstr(argvals,"genesishash",genesishash);
    if ( genesisblock != 0 && genesisblock[0] != 0  )
        jaddstr(argvals,"genesisblock",genesisblock);
    jaddstr(argvals,"netmagic",magicstr);
    jaddstr(argvals,"symbol",symbol);
    jaddstr(argvals,"name",chainname);
    if ( nbitstr == 0 || nbitstr[0] == 0 )
        nbitstr = BASILISK_DEFAULTDIFFSTR;
    jaddstr(argvals,"nbits",nbitstr);
    jaddstr(argvals,"chain",chain);
    if ( keystr != 0 )
        jaddstr(argvals,"key",keystr);
    if ( port == 0 )
        jaddstr(argvals,"privatechain",chainname);
    else
    {
        jaddnum(argvals,"services",129);
        jaddnum(argvals,"portp2p",port);
        if ( blocktime == 0xffff )
            targetspacing = 24 * 60 * 60; // one day
        else targetspacing = 60; // one minute
        jaddnum(argvals,"targetspacing",targetspacing);
        if ( (timespan= sqrt(604800 / targetspacing)) < 7 )
            timespan = 7;
        jaddnum(argvals,"targettimespan",targetspacing * timespan);
    }
    return(argvals);
}

char *basilisk_respond_newprivatechain(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk)
{
    struct iguana_info *virt,*btcd; char *symbol,*chain,chainname[BASILISK_MAXNAMELEN]; cJSON *retjson;
    if ( (virt= basilisk_chain(myinfo,chainname,valsobj)) != 0 )
    {
        printf("%s already exists\n",chainname);
        return(clonestr("{\"error\":\"cant create duplicate privatechain\"}"));
    }
    if ( (btcd= iguana_coinfind("BTCD")) != 0 && (symbol= jstr(valsobj,"symbol")) != 0 && (chain= jstr(valsobj,"chain")) != 0 )
    {
        if ( (virt= basilisk_privatechain(myinfo,symbol,chainname,valsobj)) != 0 )
        {
            retjson = basilisk_genesisargs(symbol,chainname,chain,jstr(valsobj,"key"),jstr(valsobj,"genesishash"),jstr(valsobj,"genesisblock"),jstr(valsobj,"netmagic"),juint(valsobj,"port"),juint(valsobj,"blocktime"),jstr(valsobj,"nbits"));
            jaddstr(retjson,"result","success");
            return(jprint(retjson,1));
        }
    }
    return(clonestr("{\"error\":-22}"));
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

HASH_ARRAY_STRING(basilisk,newprivatechain,pubkey,vals,hexstr)
{
    char chainname[BASILISK_MAXNAMELEN],magicstr[9],*retstr,*symbol,*chain; struct iguana_info *virt,*btcd; cJSON *argjson,*argvals,*retjson=0; int32_t i; uint32_t magic;
    if ( (btcd= iguana_coinfind("BTCD")) != 0 && (symbol= jstr(vals,"symbol")) != 0 && (chain= jstr(vals,"chain")) != 0 )
    {
        if ( iguana_coinfind(symbol) == 0 && (virt= basilisk_chain(myinfo,chainname,vals)) != 0 )
        {
            printf("%s already exists\n",chainname);
            return(clonestr("{\"error\":\"cant create duplicate privatechain\"}"));
        }
        if ( jobj(vals,"netmagic") == 0 )
        {
            OS_randombytes((void *)&magic,sizeof(magic));
            for (i=0; i<sizeof(magic); i++)
                ((uint8_t *)&magic)[i] |= 0x80;
            init_hexbytes_noT(magicstr,(void *)&magic,sizeof(magic));
        } else safecopy(magicstr,jstr(vals,"netmagic"),sizeof(magicstr));
        if ( (argjson= basilisk_genesisjson(myinfo,btcd,chainname,vals)) != 0 )
        {
            argvals = basilisk_genesisargs(symbol,chainname,chain,jstr(argjson,"key"),jstr(argjson,"genesishash"),jstr(argjson,"genesisblock"),jstr(argjson,"netmagic"),juint(argjson,"port"),juint(argjson,"blocktime"),jstr(argjson,"nbits"));
            if ( btcd->RELAYNODE != 0 || btcd->VALIDATENODE != 0 )
                retstr = basilisk_respond_newprivatechain(myinfo,"NEW",0,0,0,argvals,0,0,GENESIS_PUBKEY,0);
            else retstr = basilisk_standardservice("NEW",myinfo,GENESIS_PUBKEY,argvals,0,1);
            free_json(argvals);
            if ( (argvals= cJSON_Parse(retstr)) != 0 )
            {
                if ( jobj(argvals,"result") != 0 && strcmp(jstr(argvals,"result"),"success") == 0 )
                {
                    if ( basilisk_privatechain(myinfo,symbol,chainname,argvals) != 0 )
                        jaddstr(argvals,"status","active");
                    //free_json(argvals);
                } else jaddstr(argvals,"error","couldnt initialize privatechain");
                free(retstr);
                return(jprint(argvals,1));
            }
            if ( retjson != 0 )
                free_json(retjson);
            free_json(argvals);
            return(retstr);
        } else return(clonestr("{\"error\":\"couldnt create genesis_block\"}"));
    }
    return(clonestr("{\"error\":\"need symbol and chain and BTCD to create new private chain\"}"));
}

HASH_ARRAY_STRING(basilisk,sequence,pubkey,vals,hexstr)
{
    return(basilisk_standardservice("SEQ",myinfo,pubkey,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,set,pubkey,vals,hexstr)
{
    return(basilisk_standardservice("SET",myinfo,pubkey,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,get,pubkey,vals,hexstr)
{
    return(basilisk_standardservice("GET",myinfo,pubkey,vals,hexstr,1));
}
#include "../includes/iguana_apiundefs.h"


