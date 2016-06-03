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

char *basilisk_respond_goodbye(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    printf("(%s) sends goodbye\n",remoteaddr);
    addr->dead = (uint32_t)time(NULL);
    addr->rank = 0;
    return(0);
}

void basilisk_request_goodbye(struct supernet_info *myinfo)
{
    cJSON *valsobj = cJSON_CreateObject();
    jaddnum(valsobj,"timeout",-1);
    basilisk_requestservice(myinfo,"BYE",valsobj,GENESIS_PUBKEY,0,0,0);
    free_json(valsobj);
}

int32_t iguana_rwhashstamp(int32_t rwflag,uint8_t *serialized,struct hashstamp *stamp)
{
    int32_t len = 0;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(stamp->hash2),stamp->hash2.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(stamp->timestamp),&stamp->timestamp);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(stamp->height),&stamp->height);
    len += iguana_rwblock80(rwflag,&serialized[len],(void *)stamp->RO);
    return(len);
}

cJSON *basilisk_sequencejson(struct basilisk_sequence *seq,int32_t startheight,int32_t firstpossible)
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
        len += iguana_rwhashstamp(1,&data[len],&seq->stamps[i]);
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
                    len += iguana_rwhashstamp(0,&data[len],&stamp);
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

char *basilisk_respond_hashstamps(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk)
{
    int32_t startheight; struct iguana_info *btcd; cJSON *retjson = cJSON_CreateObject();
    if ( (btcd= iguana_coinfind("BTCD")) != 0 )
    {
        if ( (startheight= juint(valsobj,"BTCD")) != 0 )
            jadd(retjson,"BTCD",basilisk_sequencejson(&btcd->SEQ.BTCD,startheight,BASILISK_FIRSTPOSSIBLEBTCD));
        else if ( (startheight= juint(valsobj,"BTC")) != 0 )
            jadd(retjson,"BTC",basilisk_sequencejson(&btcd->SEQ.BTC,startheight,BASILISK_FIRSTPOSSIBLEBTC));
    }
    return(jprint(retjson,1));
}

char *basilisk_respond_setfield(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk)
{
    struct iguana_info *coin; struct iguana_block *prevblock,*prev2,*newblock,block; char str[65],*blocktx; uint32_t nBits,timestamp,nonce; cJSON *retjson; bits256 btcdhash;
    if ( datalen <= 0 )
        return(clonestr("{\"error\":\"no data specified\"}"));
    if ( (coin= basilisk_chain(myinfo,valsobj)) == 0 )
        return(clonestr("{\"error\":\"couldnt get basilisk_chain\"}"));
    printf("from.(%s) SET.(%s) datalen.%d prev.%s\n",remoteaddr,jprint(valsobj,0),datalen,bits256_str(str,prevhash));
    if ( bits256_nonz(prevhash) == 0 )
        prevhash = coin->blocks.hwmchain.RO.hash2;
    if ( (prevblock= iguana_blockfind("setfield",coin,prevhash)) == 0 )
        return(clonestr("{\"error\":\"couldnt find prevhash\"}"));
    if ( (prev2= iguana_blockfind("setfield",coin,prevblock->RO.prev_block)) == 0 )
        return(clonestr("{\"error\":\"couldnt find prevhash2\"}"));
    timestamp = juint(valsobj,"timestamp");
    nonce = juint(valsobj,"nonce");
    nBits = iguana_targetbits(coin,&coin->blocks.hwmchain,prevblock,prev2,1,coin->chain->targetspacing,coin->chain->targettimespan);
    blocktx = basilisk_block(myinfo,coin,&block,1,timestamp,&nonce,prevhash,nBits,prevblock->height+1,0,0,data,datalen,btcdhash,jobj(valsobj,"coinbase"));
    retjson = cJSON_CreateObject();
    jaddbits256(retjson,"hash",block.RO.hash2);
    jaddstr(retjson,"data",blocktx);
    if ( (newblock= _iguana_chainlink(coin,&block)) != 0 )
    {
        jaddstr(retjson,"result","chain extended");
        jaddnum(retjson,"ht",block.height);
    } else jaddstr(retjson,"error","couldnt extend chain");
    free(blocktx);
    return(jprint(retjson,1));
}

char *basilisk_respond_getfield(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk)
{
    struct iguana_info *coin; cJSON *retjson;
    if ( (coin= basilisk_chain(myinfo,valsobj)) == 0 )
        return(clonestr("{\"error\":\"couldnt get basilisk_chain\"}"));
    printf("getfield\n");
    retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

char *basilisk_respond_publish(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    printf("from.(%s) PUB.(%s) datalen.%d\n",remoteaddr,jprint(valsobj,0),datalen);
    return(retstr);
}

char *basilisk_respond_subscribe(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    printf("from.(%s) SUB.(%s) datalen.%d\n",remoteaddr,jprint(valsobj,0),datalen);
    return(retstr);
}

char *basilisk_respond_dispatch(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_addrelay(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_forward(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_mailbox(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_VPNcreate(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_VPNjoin(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_VPNlogout(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_VPNbroadcast(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_VPNreceive(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}

char *basilisk_respond_VPNmessage(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 pubkey,int32_t from_basilisk)
{
    char *retstr=0;
    return(retstr);
}


