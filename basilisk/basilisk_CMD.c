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
    return(len);
}

cJSON *basilisk_sequencejson(struct basilisk_sequence *seq,int32_t startheight,int32_t firstpossible)
{
    int32_t i,n,len=0,num = 0; cJSON *item; uint8_t *data;
    if ( startheight < firstpossible )
        startheight = firstpossible;
    if ( (i= (startheight - firstpossible) ) < 0 || i >= seq->numstamps )
        return(0);
    item = cJSON_CreateObject();
    n = (seq->numstamps - i);
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
    return(item);
}

char *basilisk_respond_hashstamps(struct supernet_info *myinfo,char *CMD,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 prevhash,int32_t from_basilisk)
{
    int32_t doneflag; struct iguana_info *btcd; cJSON *retjson = cJSON_CreateObject();
    if ( (btcd= iguana_coinfind("BTCD")) != 0 && (doneflag= juint(valsobj,"done")) != 3 )
    {
        if ( (doneflag & 1) == 0 )
            jadd(retjson,"BTCD",basilisk_sequencejson(&btcd->SEQ.BTCD,juint(valsobj,"BTCD"),BASILISK_FIRSTPOSSIBLEBTCD));
        else if ( (doneflag & 2) == 0 )
            jadd(retjson,"BTC",basilisk_sequencejson(&btcd->SEQ.BTC,juint(valsobj,"BTC"),BASILISK_FIRSTPOSSIBLEBTC));
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


