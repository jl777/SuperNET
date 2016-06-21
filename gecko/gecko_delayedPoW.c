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

int32_t gecko_hashstampsfind(struct hashstamp *stamps,int32_t max,struct gecko_sequence *seq,bits256 hash,uint32_t reftimestamp)
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

bits256 gecko_hashstampscalc(struct supernet_info *myinfo,struct iguana_info *btcd,bits256 *btchashp,uint32_t reftimestamp)
{
    struct hashstamp BTCDstamps[GECKO_MAXBTCDGAP],BTCstamps[GECKO_MAXBTCGAP]; bits256 btcdhash;
    btcdhash = *btchashp = GENESIS_PUBKEY;
    if ( gecko_hashstampsfind(BTCDstamps,GECKO_MAXBTCDGAP,&myinfo->dPOW.SEQ.BTCD,btcdhash,reftimestamp) < 0 )
    {
        btcdhash = BTCDstamps[GECKO_MAXBTCDGAP >> 1].hash2;
        if ( gecko_hashstampsfind(BTCstamps,GECKO_MAXBTCGAP,&myinfo->dPOW.SEQ.BTC,*btchashp,reftimestamp) < 0 )
            *btchashp = BTCstamps[GECKO_MAXBTCGAP >> 1].hash2;
    }
    return(btcdhash);
}

// have local coin
int32_t gecko_hashstampsreverse(struct iguana_info *coin,struct gecko_sequence *seq,int32_t firstpossible,int32_t max,struct iguana_block *block,uint32_t reftimestamp)
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

int32_t gecko_hashstampset(struct iguana_info *coin,struct hashstamp *stamp,int32_t height)
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

void gecko_ensure(struct gecko_sequence *seq,int32_t num)
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

int32_t gecko_hashstampsupdate(struct iguana_info *coin,struct gecko_sequence *seq,int32_t firstpossible)
{
    while ( (firstpossible + seq->numstamps) < coin->blocks.hwmchain.height )
    {
        gecko_ensure(seq,seq->numstamps);
        if ( gecko_hashstampset(coin,&seq->stamps[seq->numstamps],firstpossible + seq->numstamps) < 0 )
            break;
        else seq->numstamps++;
    }
    seq->longestchain = coin->longestchain;
    return(seq->numstamps);
}

int32_t gecko_sequpdate(struct supernet_info *myinfo,char *symbol,uint32_t reftimestamp)
{
    struct gecko_sequence *seq=0; int32_t max=0,firstpossible=0; struct iguana_info *coin; struct iguana_block *block;
    if ( (coin= iguana_coinfind(symbol)) != 0 && (coin->RELAYNODE != 0 || coin->VALIDATENODE != 0) )
    {
        if ( strcmp(symbol,"BTCD") == 0 )
        {
            seq = &myinfo->dPOW.SEQ.BTCD;
            firstpossible = GECKO_FIRSTPOSSIBLEBTCD;
        }
        else if ( strcmp(symbol,"BTC") == 0 )
        {
            seq = &myinfo->dPOW.SEQ.BTC;
            firstpossible = GECKO_FIRSTPOSSIBLEBTC;
        } else return(-1);
        //printf("basilisk update.%s %u lag.%d\n",symbol,reftimestamp,(uint32_t)time(NULL)-seq->lastupdate);
        if ( gecko_hashstampsupdate(coin,seq,firstpossible) > 0 )
        {
            if ( (block= iguana_blockfind("SEQupdate",coin,coin->blocks.hwmchain.RO.hash2)) != 0 )
                gecko_hashstampsreverse(coin,seq,firstpossible,max,block,reftimestamp);
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

cJSON *gecko_sequencejson(uint8_t zcash,struct gecko_sequence *seq,int32_t startheight,int32_t firstpossible)
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

void gecko_seqresult(struct supernet_info *myinfo,char *retstr)
{
    struct iguana_info *btcd; struct hashstamp stamp; struct gecko_sequence *seq = 0; cJSON *resultjson; uint8_t *allocptr = 0,space[8192],*data = 0; int32_t ind,startheight,datalen,lastupdate,longestchain,i,num,firstpossible,len = 0; char *hexstr;
    if ( (btcd= iguana_coinfind("BTCD")) != 0 && (resultjson= cJSON_Parse(retstr)) != 0 )
    {
        if ( jstr(resultjson,"BTCD") != 0 )
            seq = &myinfo->dPOW.SEQ.BTCD, firstpossible = GECKO_FIRSTPOSSIBLEBTCD;
        else if ( jstr(resultjson,"BTC") != 0 )
            seq = &myinfo->dPOW.SEQ.BTC, firstpossible = GECKO_FIRSTPOSSIBLEBTC;
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
            if ( hexstr != 0 && (data= get_dataptr(BASILISK_HDROFFSET,&allocptr,&datalen,space,sizeof(space),hexstr)) != 0 )
            {
                gecko_ensure(seq,ind + num);
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
            jadd(retjson,"BTCD",gecko_sequencejson(btcd->chain->zcash,&myinfo->dPOW.SEQ.BTCD,startheight,GECKO_FIRSTPOSSIBLEBTCD));
        else if ( (startheight= juint(valsobj,"BTC")) != 0 )
            jadd(retjson,"BTC",gecko_sequencejson(btcd->chain->zcash,&myinfo->dPOW.SEQ.BTC,startheight,GECKO_FIRSTPOSSIBLEBTC));
    }
    return(jprint(retjson,1));
}

/*
done = 3;
if ( btcd->RELAYNODE != 0 || btcd->VALIDATENODE != 0 )
{
    if ( (now= (uint32_t)time(NULL)) > myinfo->dPOW.SEQ.BTCD.lastupdate+10 )
    {
        if ( gecko_sequpdate(myinfo,"BTCD",now) >= 0 )
            done &= ~1;
        myinfo->dPOW.SEQ.BTCD.lastupdate = (uint32_t)time(NULL);
    }
}
if ( (now= (uint32_t)time(NULL)) > myinfo->dPOW.SEQ.BTC.lastupdate+30 )
{
    if ( gecko_sequpdate(myinfo,"BTC",now) >= 0 )
        done &= ~2;
        myinfo->dPOW.SEQ.BTC.lastupdate = (uint32_t)time(NULL);
        }
if ( done != 3 )
{
    valsobj = cJSON_CreateObject();
    if ( btcd->RELAYNODE == 0 && btcd->VALIDATENODE == 0 )
    {
        //fprintf(stderr,"e");
        jaddnum(valsobj,"BTCD",myinfo->dPOW.SEQ.BTCD.numstamps+GECKO_FIRSTPOSSIBLEBTCD);
        basilisk_standardservice("SEQ",myinfo,GENESIS_PUBKEY,valsobj,0,0);
        flag++;
    }
    if ( (done & 2) == 0 )
    {
        //fprintf(stderr,"f");
        free_json(valsobj);
        valsobj = cJSON_CreateObject();
        jaddnum(valsobj,"BTC",myinfo->dPOW.SEQ.BTC.numstamps+GECKO_FIRSTPOSSIBLEBTC);
        basilisk_standardservice("SEQ",myinfo,GENESIS_PUBKEY,valsobj,0,0);
        flag++;
    }
    free_json(valsobj);
}
*/