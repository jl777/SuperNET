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

typedef char *basilisk_servicefunc(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk);

uint32_t basilisk_calcnonce(struct supernet_info *myinfo,uint8_t *data,int32_t datalen,uint32_t nBits)
{
    int32_t i,numiters = 0; bits256 hash,hash2,threshold; uint32_t basilisktag;
    vcalc_sha256(0,hash.bytes,data,datalen);
    if ( nBits >= GECKO_EASIESTDIFF )
        threshold = bits256_from_compact(GECKO_EASIESTDIFF);
    else threshold = bits256_from_compact(nBits);
    for (i=0; i<numiters; i++)
    {
        //OS_randombytes((void *)hash.uints,sizeof(basilisktag));
        hash.uints[0] = rand();
        vcalc_sha256(0,hash2.bytes,hash.bytes,sizeof(hash));
        if ( bits256_cmp(threshold,hash2) > 0 )
            break;
    }
    iguana_rwnum(0,(void *)hash.uints,sizeof(basilisktag),&basilisktag);
    iguana_rwnum(1,&data[-sizeof(basilisktag)],sizeof(basilisktag),&basilisktag);
    char str[65],str2[65]; printf("found hash after numiters.%d %s vs %s basilisktag.%u\n",numiters,bits256_str(str,threshold),bits256_str(str2,hash2),basilisktag);
    return(basilisktag);
}

char *basilisk_addhexstr(char **ptrp,cJSON *valsobj,char *strbuf,int32_t strsize,uint8_t *data,int32_t datalen)
{
    *ptrp = 0;
    if ( data != 0 && datalen > 0 )
    {
        if ( valsobj != 0 && jobj(valsobj,"data") != 0 )
        {
            printf("basilisk_addhexstr warning: already have data object\n");
            jdelete(valsobj,"data");
        }
        if ( (datalen<<1)+1 > strsize )
        {
            strbuf = calloc(1,(datalen << 1) + 1);
            *ptrp = (void *)strbuf;
        }
        init_hexbytes_noT(strbuf,data,datalen);
        if ( valsobj != 0 )
            jaddstr(valsobj,"data",strbuf);
    } else return(0);
    return(strbuf);
}

uint8_t *get_dataptr(int32_t hdroffset,uint8_t **ptrp,int32_t *datalenp,uint8_t *space,int32_t spacesize,char *hexstr)
{
    *ptrp = 0; uint8_t *data = 0;
    if ( hexstr != 0 && (*datalenp= is_hexstr(hexstr,0)) > 0 )
    {
        *datalenp >>= 1;
        if ( (*datalenp+hdroffset) <= spacesize )
        {
            memset(space,0,hdroffset);
            data = &space[hdroffset];
        } else *ptrp = data = calloc(1,*datalenp + hdroffset);
        decode_hex(&data[hdroffset],*datalenp,hexstr);
    }
    if ( data != 0 )
        return(&data[hdroffset]);
    else return(data);
}

uint8_t *basilisk_jsondata(int32_t extraoffset,uint8_t **ptrp,uint8_t *space,int32_t spacesize,int32_t *datalenp,char *symbol,cJSON *sendjson,uint32_t basilisktag)
{
    char *sendstr,*hexstr=0; uint8_t *data,hexspace[4096],*allocptr=0,*hexdata; int32_t datalen,hexlen=0;
    if ( jobj(sendjson,"symbol") == 0 )
        jaddstr(sendjson,"symbol",symbol);
    if ( (hexstr= jstr(sendjson,"data")) != 0 )
    {
        hexdata = get_dataptr(0,&allocptr,&hexlen,hexspace,sizeof(hexspace),hexstr);
        //printf("jsondata.%s from sendjson\n",hexstr);
        jdelete(sendjson,"data");
    }
    *ptrp = 0;
    sendstr = jprint(sendjson,0);
    datalen = (int32_t)strlen(sendstr) + 1;
    if ( (datalen + extraoffset + BASILISK_HDROFFSET + hexlen) <= spacesize )
        data = space;
    else
    {
        data = calloc(1,datalen + extraoffset + BASILISK_HDROFFSET + hexlen);
        *ptrp = data;
    }
    data += extraoffset + BASILISK_HDROFFSET;
    memcpy(data,sendstr,datalen);
    //printf("jsondata.(%s) + hexlen.%d\n",sendstr,hexlen);
    free(sendstr);
    if ( hexlen > 0 )
    {
        //int32_t i; for (i=0; i<hexlen; i++)
        //    printf("%02x",hexdata[i]);
        //printf(" <- hexdata\n");
        memcpy(&data[datalen],hexdata,hexlen);
        datalen += hexlen;
    }
    *datalenp = datalen;
    if ( allocptr != 0 )
        free(allocptr);
    return(data);
}

struct basilisk_item *basilisk_itemcreate(struct supernet_info *myinfo,char *CMD,char *symbol,uint32_t basilisktag,int32_t minresults,cJSON *vals,int32_t timeoutmillis,void *metricfunc)
{
    struct basilisk_item *ptr;
    ptr = calloc(1,sizeof(*ptr));
    ptr->basilisktag = basilisktag;
    if ( (ptr->numrequired= minresults) == 0 )
        ptr->numrequired = 1;
    strcpy(ptr->CMD,CMD);
    safecopy(ptr->symbol,symbol,sizeof(ptr->symbol));
    ptr->expiration = OS_milliseconds() + timeoutmillis;
    return(ptr);
}

int32_t basilisk_specialrelay_CMD(char *CMD)
{
    if ( strcmp(CMD,"BLK") == 0 || strcmp(CMD,"MEM") == 0 || strcmp(CMD,"GTX") == 0 || strcmp(CMD,"OUT") == 0 || strcmp(CMD,"MSG") == 0 )
        return(1);
    else return(0);
}

int32_t basilisk_sendcmd(struct supernet_info *myinfo,char *destipaddr,char *type,uint32_t *basilisktagp,int32_t encryptflag,int32_t delaymillis,uint8_t *data,int32_t datalen,int32_t fanout,uint32_t nBits) // data must be offset by sizeof(iguana_msghdr)+sizeof(basilisktag)
{
    int32_t i,r,l,s,val,n=0,retval = -1; char cmd[12]; struct iguana_info *coin,*tmp; struct iguana_peer *addr; bits256 hash; uint32_t *alreadysent;
    if ( fanout <= 0 )
        fanout = BASILISK_MINFANOUT;
    else if ( fanout > BASILISK_MAXFANOUT )
        fanout = BASILISK_MAXFANOUT;
    if ( type == 0 )
        type = "BTCD";
    if ( strlen(type) > 3 )
    {
        printf("basilisk_sendcmd illegal type(%s)\n",type);
        return(-1);
    }
    if ( destipaddr != 0 )
    {
        if ( destipaddr[0] == 0 )
            destipaddr = 0; // broadcast
        else if ( strcmp(destipaddr,"127.0.0.1") == 0 || strcmp(destipaddr,myinfo->ipaddr) == 0 )
        {
            printf("return after locally basilisk_msgprocess\n");
            hash = GENESIS_PUBKEY;
            basilisk_msgprocess(myinfo,0,0,type,*basilisktagp,data,datalen);
            return(0);
        }
    }
    alreadysent = calloc(IGUANA_MAXPEERS * IGUANA_MAXCOINS,sizeof(*alreadysent));
    iguana_rwnum(1,&data[-sizeof(*basilisktagp)],sizeof(*basilisktagp),basilisktagp);
    if ( *basilisktagp == 0 )
    {
        if ( nBits != 0 )
            *basilisktagp = basilisk_calcnonce(myinfo,data,datalen,nBits);
        else *basilisktagp = rand();
        iguana_rwnum(1,&data[-sizeof(*basilisktagp)],sizeof(*basilisktagp),basilisktagp);
    }
    data -= sizeof(*basilisktagp), datalen += sizeof(*basilisktagp);
    memset(cmd,0,sizeof(cmd));
    sprintf(cmd,"SuperNET%s",type);
    //portable_mutex_lock(&myinfo->allcoins_mutex);
    HASH_ITER(hh,myinfo->allcoins,coin,tmp)
    {
        if (  coin->peers == 0 )
            continue;
        if ( coin->RELAYNODE == 0 && coin->VALIDATENODE == 0 )
            cmd[0] = 's';
        else cmd[0] = 'S';
        r = rand() % (coin->peers->numranked+1);
        for (l=0; l<IGUANA_MAXPEERS; l++)
        {
            i = (l + r) % IGUANA_MAXPEERS;
            addr = &coin->peers->active[i];
            if ( 0 && addr->ipaddr[0] != 0 )
                printf("%s %s s.%d vs n.%d iguana.%d\n",coin->symbol,addr->ipaddr,s,n,addr->supernet);
            if ( addr->usock >= 0 )
            {
                if ( basilisk_specialrelay_CMD(type) > 0 )
                {
                    for (s=0; s<myinfo->numrelays; s++)
                        if ( addr->ipbits != myinfo->myaddr.myipbits && myinfo->relays[s].ipbits == addr->ipbits )
                            break;
                    if ( s == myinfo->numrelays )
                    {
                        //printf("skip non-relay.(%s)\n",addr->ipaddr);
                        continue;
                    }
                    ///printf("send to other relay.(%s)\n",addr->ipaddr);
                }
                for (s=0; s<n; s++)
                    if ( alreadysent[s] == addr->ipbits )
                        continue;
                if ( s == n && (addr->supernet != 0 || addr->basilisk != 0) && (destipaddr == 0 || strcmp(addr->ipaddr,destipaddr) == 0) )
                {
                    //printf("i.%d l.%d [%s].tag%d send %s.(%s) [%x] datalen.%d addr->supernet.%u basilisk.%u to (%s).%d destip.%s\n",i,l,cmd,*(uint32_t *)data,type,(char *)&data[4],*(int32_t *)&data[datalen-4],datalen,addr->supernet,addr->basilisk,addr->ipaddr,addr->A.port,destipaddr!=0?destipaddr:"broadcast");
                    if ( encryptflag != 0 && bits256_nonz(addr->pubkey) != 0 )
                    {
                        void *ptr; uint8_t *cipher,space[8192]; int32_t cipherlen; bits256 privkey;
                        cmd[6] = 'e', cmd[7] = 't';
                        memset(privkey.bytes,0,sizeof(privkey));
                        if ( (cipher= SuperNET_ciphercalc(&ptr,&cipherlen,&privkey,&addr->pubkey,data,datalen,space,sizeof(space))) != 0 )
                        {
                            if ( (val= iguana_queue_send(addr,delaymillis,&cipher[-sizeof(struct iguana_msghdr)],cmd,cipherlen)) >= cipherlen )
                                n++;
                            if ( ptr != 0 )
                                free(ptr);
                        }
                    }
                    else
                    {
                        cmd[6] = 'E', cmd[7] = 'T';
                        if ( (val= iguana_queue_send(addr,delaymillis,&data[-sizeof(struct iguana_msghdr)],cmd,datalen)) >= datalen )
                        {
                            alreadysent[n++] = (uint32_t)addr->ipbits;
                            if ( n >= IGUANA_MAXPEERS*IGUANA_MAXCOINS )
                                break;
                        }
                    }
                    if ( destipaddr != 0 || (fanout > 0 && n >= fanout) )
                    {
                        free(alreadysent);
                        return(val);
                    }
                    else if ( val > retval )
                        retval = val;
                }
            }
        }
        if ( n >= IGUANA_MAXPEERS*IGUANA_MAXCOINS )
            break;
    }
    //portable_mutex_unlock(&myinfo->allcoins_mutex);
    free(alreadysent);
    return(n);
}

void basilisk_sendback(struct supernet_info *myinfo,char *origCMD,char *symbol,char *remoteaddr,uint32_t basilisktag,char *retstr)
{
    uint8_t *data,space[4096],*allocptr; struct iguana_info *virt; cJSON *valsobj; int32_t datalen,encryptflag=0,delaymillis=0;
    //printf("%s retstr.(%s) -> remote.(%s) basilisktag.%u\n",origCMD,retstr,remoteaddr,basilisktag);
    if ( retstr != 0 && remoteaddr != 0 && remoteaddr[0] != 0 && strcmp(remoteaddr,"127.0.0.1") != 0 )
    {
        if ( (valsobj= cJSON_Parse(retstr)) != 0 )
        {
            jaddstr(valsobj,"origcmd",origCMD);
            jaddstr(valsobj,"symbol",symbol);
            if ( myinfo->ipaddr[0] != 0 )
                jaddstr(valsobj,"relay",myinfo->ipaddr);
            if ( (virt= iguana_coinfind(symbol)) != 0 )
            {
                jaddnum(valsobj,"hwm",virt->blocks.hwmchain.height);
                jaddbits256(valsobj,"chaintip",virt->blocks.hwmchain.RO.hash2);
            }
            data = basilisk_jsondata(sizeof(struct iguana_msghdr),&allocptr,space,sizeof(space),&datalen,symbol,valsobj,basilisktag);
            basilisk_sendcmd(myinfo,remoteaddr,"RET",&basilisktag,encryptflag,delaymillis,data,datalen,0,0);
            if ( allocptr != 0 )
                free(allocptr);
            free_json(valsobj);
        }
    }
}

struct basilisk_item *basilisk_issueremote(struct supernet_info *myinfo,struct iguana_peer *addr,int32_t *numsentp,char *CMD,char *symbol,int32_t blockflag,cJSON *valsobj,int32_t fanout,int32_t minresults,uint32_t basilisktag,int32_t timeoutmillis,void *deprecated_dontuse,char *retstr,int32_t encryptflag,int32_t delaymillis,uint32_t nBits)
{
    struct basilisk_item *pending; uint8_t *allocptr,*data,space[4096]; int32_t datalen; cJSON *retarray;
    pending = basilisk_itemcreate(myinfo,CMD,symbol,basilisktag,minresults,valsobj,timeoutmillis,0);
    pending->nBits = nBits;
    *numsentp = 0;
    if ( retstr != 0 )
    {
        pending->retstr = retstr;
        pending->numresults = pending->numrequired;
    }
    else
    {
        valsobj = jduplicate(valsobj);
        data = basilisk_jsondata(sizeof(struct iguana_msghdr),&allocptr,space,sizeof(space),&datalen,symbol,valsobj,basilisktag);
        free_json(valsobj), valsobj = 0;
        *numsentp = pending->numsent = basilisk_sendcmd(myinfo,addr != 0 ? addr->ipaddr : 0,CMD,&pending->basilisktag,encryptflag,delaymillis,data,datalen,fanout,pending->nBits);
        if ( blockflag != 0 )
        {
            portable_mutex_lock(&myinfo->basilisk_mutex);
            //printf("HASH_ADD.%p\n",pending);
            HASH_ADD(hh,myinfo->basilisks.issued,basilisktag,sizeof(basilisktag),pending);
            portable_mutex_unlock(&myinfo->basilisk_mutex);
            //queue_enqueue("issuedQ",&myinfo->basilisks.issued,&pending->DL,0);
            if ( pending->expiration <= OS_milliseconds() )
                pending->expiration = OS_milliseconds() + BASILISK_TIMEOUT;
            //ptr->vals = jduplicate(valsobj);
            strcpy(pending->symbol,"BTCD");
            strcpy(pending->CMD,CMD);
            while ( OS_milliseconds() < pending->expiration )
            {
                if ( pending->numresults >= pending->numrequired )//|| (retstr= pending->retstr) != 0 )
                {
                    //printf("numresults.%d vs numrequired.%d\n",pending->numresults,pending->numrequired);
                    break;
                }
                usleep(10000);
            }
            if ( (retarray= pending->retarray) != 0 )
            {
                pending->retstr = jprint(retarray,0);
                pending->retarray = 0;
                free_json(retarray);
            }
            //return(basilisk_waitresponse(myinfo,CMD,"BTCD",0,&Lptr,valsobj,ptr));
        } else free(pending), pending = 0; //ptr->finished = (uint32_t)time(NULL);
        if ( allocptr != 0 )
            free(allocptr);
    }
    return(pending);
}

struct basilisk_item *basilisk_requestservice(struct supernet_info *myinfo,struct iguana_peer *addr,char *CMD,int32_t blockflag,cJSON *valsobj,bits256 hash,uint8_t *data,int32_t datalen,uint32_t nBits)
{
    int32_t numrequired,timeoutmillis,numsent,delaymillis,encryptflag,fanout; struct basilisk_item *ptr; char buf[4096],*symbol,*str = 0; struct iguana_info *virt;
    //printf("request.(%s)\n",jprint(valsobj,0));
    basilisk_addhexstr(&str,valsobj,buf,sizeof(buf),data,datalen);
    if ( bits256_cmp(hash,GENESIS_PUBKEY) != 0 && bits256_nonz(hash) != 0 )
    {
        if ( jobj(valsobj,"hash") != 0 )
            jdelete(valsobj,"hash");
        jaddbits256(valsobj,"hash",hash);
    }
    if ( (numrequired= jint(valsobj,"numrequired")) <= 0 )
        numrequired = 1;
    if ( (timeoutmillis= jint(valsobj,"timeout")) == 0 )
        timeoutmillis = BASILISK_TIMEOUT;
    if ( jobj(valsobj,"fanout") == 0 )
        fanout = 1;
    else fanout = jint(valsobj,"fanout");
    if ( (symbol= jstr(valsobj,"coin")) != 0 || (symbol= jstr(valsobj,"symbol")) != 0 )
    {
        if ( (virt= iguana_coinfind(symbol)) != 0 )
        {
            jaddstr(valsobj,"symbol",symbol);
            jaddnum(valsobj,"longest",virt->longestchain);
            jaddnum(valsobj,"hwm",virt->blocks.hwmchain.height);
        }
    }
    if ( symbol == 0 )
        symbol = "BTCD";
    encryptflag = jint(valsobj,"encrypt");
    delaymillis = jint(valsobj,"delay");
    ptr = basilisk_issueremote(myinfo,addr,&numsent,CMD,symbol,blockflag,valsobj,fanout,numrequired,0,timeoutmillis,0,0,encryptflag,delaymillis,nBits);
    return(ptr);
}

char *basilisk_standardservice(char *CMD,struct supernet_info *myinfo,void *_addr,bits256 hash,cJSON *valsobj,char *hexstr,int32_t blockflag) // client side
{
    uint32_t nBits = 0; uint8_t space[4096],*allocptr=0,*data = 0; struct basilisk_item *ptr; int32_t datalen = 0; cJSON *retjson; char *retstr=0;
    data = get_dataptr(BASILISK_HDROFFSET,&allocptr,&datalen,space,sizeof(space),hexstr);
    ptr = basilisk_requestservice(myinfo,_addr,CMD,blockflag,valsobj,hash,data,datalen,nBits);
    if ( allocptr != 0 )
        free(allocptr);
    if ( ptr != 0 )
    {
        if ( ptr->retstr != 0 )
            retstr = ptr->retstr, ptr->retstr = 0;
        else
        {
            retjson = cJSON_CreateObject();
            if ( ptr->numsent > 0 )
            {
                //queue_enqueue("submitQ",&myinfo->basilisks.submitQ,&ptr->DL,0);
                jaddstr(retjson,"result","success");
                jaddnum(retjson,"numsent",ptr->numsent);
            } else jaddstr(retjson,"error","didnt find any nodes to send to");
            retstr = jprint(retjson,1);
        }
        ptr->finished = (uint32_t)time(NULL);
    }
    if ( 0 && strcmp("RID",CMD) != 0 )
        printf("%s.(%s) -> (%s)\n",CMD,jprint(valsobj,0),retstr!=0?retstr:"");
    return(retstr);
}

int32_t basilisk_relayid(struct supernet_info *myinfo,uint32_t ipbits)
{
    int32_t j;
    for (j=0; j<myinfo->numrelays; j++)
        if ( myinfo->relays[j].ipbits == ipbits )
            return(j);
    return(-1);
}

#include "basilisk_bitcoin.c"
#include "basilisk_nxt.c"
#include "basilisk_ether.c"
#include "basilisk_waves.c"
#include "basilisk_lisk.c"

#include "basilisk_MSG.c"
#include "basilisk_tradebot.c"
#include "basilisk_swap.c"
#include "basilisk_DEX.c"
#include "basilisk_ping.c"
#include "basilisk_CMD.c"

void basilisk_functions(struct iguana_info *coin,int32_t protocol)
{
    coin->protocol = protocol;
    switch ( protocol )
    {
        /*case IGUANA_PROTOCOL_BITCOIN:
            coin->basilisk_balances = basilisk_bitcoinbalances;
            coin->basilisk_rawtx = basilisk_bitcoinrawtx;
            //coin->basilisk_rawtxmetric = basilisk_bitcoin_rawtxmetric;
            coin->basilisk_value = basilisk_bitcoinvalue;
            coin->basilisk_valuemetric = basilisk_bitcoin_valuemetric;
            break;
        case IGUANA_PROTOCOL_IOTA:
            coin->basilisk_balances = basilisk_iotabalances;
            coin->basilisk_rawtx = basilisk_iotarawtx;
            break;
        case IGUANA_PROTOCOL_NXT:
            coin->basilisk_balances = basilisk_nxtbalances;
            coin->basilisk_rawtx = basilisk_nxtrawtx;
            break;
        case IGUANA_PROTOCOL_ETHER:
            coin->basilisk_balances = basilisk_etherbalances;
            coin->basilisk_rawtx = basilisk_etherrawtx;
            break;
        case IGUANA_PROTOCOL_WAVES:
            coin->basilisk_balances = basilisk_wavesbalances;
            coin->basilisk_rawtx = basilisk_wavesrawtx;
            break;
        case IGUANA_PROTOCOL_LISK:
            coin->basilisk_balances = basilisk_liskbalances;
            coin->basilisk_rawtx = basilisk_liskrawtx;
            break;*/
    }
}

int32_t basilisk_hashes_send(struct supernet_info *myinfo,struct iguana_info *virt,struct iguana_peer *addr,char *CMD,bits256 *hashes,int32_t num)
{
    bits256 hash; uint8_t *serialized; int32_t i,len = 0; char *str=0,*retstr,*hexstr,*allocptr=0,space[4096]; bits256 txid; cJSON *vals;
    if ( virt != 0 && addr != 0 )
    {
        memset(hash.bytes,0,sizeof(hash));
        serialized = (void *)hashes;
        for (i=0; i<num; i++)
        {
            txid = hashes[i];
            len += iguana_rwbignum(1,&serialized[len],sizeof(txid),txid.bytes);
        }
        if ( (hexstr= basilisk_addhexstr(&str,0,space,sizeof(space),serialized,len)) != 0 )
        {
            vals = cJSON_CreateObject();
            jaddstr(vals,"symbol",virt->symbol);
            if ( (retstr= basilisk_standardservice(CMD,myinfo,addr,hash,vals,hexstr,0)) != 0 )
                free(retstr);
            free_json(vals);
            if ( allocptr != 0 )
                free(allocptr);
        }
        return(0);
    } else return(-1);
}

void basilisk_geckoresult(struct supernet_info *myinfo,char *remoteaddr,char *retstr,uint8_t *data,int32_t datalen)
{
    struct iguana_info *virt; char *symbol,*str,*type; cJSON *retjson; bits256 hash2;
    if ( retstr != 0 && (retjson= cJSON_Parse(retstr)) != 0 )
    {
        if ( (symbol= jstr(retjson,"symbol")) != 0 && (virt= iguana_coinfind(symbol)) != 0 )
        {
            if ( data != 0 )
            {
                str = 0;
                if ( (type= jstr(retjson,"type")) != 0 )
                {
                    hash2 = jbits256(retjson,"hash");
                    if ( strcmp(type,"HDR") == 0 )
                        str = gecko_headersarrived(myinfo,virt,remoteaddr,data,datalen,hash2);
                    else if ( strcmp(type,"MEM") == 0 )
                        str = gecko_mempoolarrived(myinfo,virt,remoteaddr,data,datalen,hash2);
                    else if ( strcmp(type,"BLK") == 0 )
                        str = gecko_blockarrived(myinfo,virt,remoteaddr,data,datalen,hash2,0);
                    else if ( strcmp(type,"GTX") == 0 )
                        str = gecko_txarrived(myinfo,virt,remoteaddr,data,datalen,hash2);
                }
                if ( str != 0 )
                    free(str);
            }
        }
        free_json(retjson);
    }
}

void basilisk_result(struct supernet_info *myinfo,char *remoteaddr,uint32_t basilisktag,cJSON *vals,uint8_t *data,int32_t datalen)
{
    char *retstr,CMD[16]; struct basilisk_item *pending; cJSON *item;
    if ( vals != 0 )
    {
        retstr = jprint(vals,0);
        safecopy(CMD,jstr(vals,"origcmd"),sizeof(CMD));
        if ( 0 && strcmp("RID",CMD) != 0 )
            printf("(%s) -> Q.%u results vals.(%s)\n",CMD,basilisktag,retstr);
        if ( strcmp(CMD,"GET") == 0 )
            basilisk_geckoresult(myinfo,remoteaddr,retstr,data,datalen);
        else
        {
            portable_mutex_lock(&myinfo->basilisk_mutex);
            HASH_FIND(hh,myinfo->basilisks.issued,&basilisktag,sizeof(basilisktag),pending);
            //printf("HASH_FIND.%p\n",pending);
            portable_mutex_unlock(&myinfo->basilisk_mutex);
            if ( pending != 0 && retstr != 0 )
            {
                if ( (item= cJSON_Parse(retstr)) != 0 )
                {
                    if ( pending->retarray == 0 )
                        pending->retarray = cJSON_CreateArray();
                    if ( jobj(item,"myip") == 0 )
                        jaddstr(item,"myip",myinfo->ipaddr);
                    jaddi(pending->retarray,item);
                } else printf("couldnt parse.(%s)\n",retstr);
                pending->numresults++;
            } else printf("couldnt find issued.%u\n",basilisktag);
        }
    }
}

void basilisk_wait(struct supernet_info *myinfo,struct iguana_info *coin)
{
    if ( coin != 0 )
    {
        while ( coin->basilisk_busy != 0 )
            usleep(1000);
    }
    else
    {
        while ( myinfo->basilisk_busy != 0 )
            usleep(1000);
    }
}

void basilisk_msgprocess(struct supernet_info *myinfo,void *_addr,uint32_t senderipbits,char *type,uint32_t basilisktag,uint8_t *data,int32_t datalen)
{
    cJSON *valsobj; char *symbol,*retstr=0,remoteaddr[64],CMD[4],cmd[4]; int32_t height,origlen,from_basilisk,i,timeoutmillis,flag,numrequired,jsonlen; uint8_t *origdata; struct iguana_info *coin=0; bits256 hash; struct iguana_peer *addr = _addr;
    static basilisk_servicefunc *basilisk_services[][2] =
    {
        { (void *)"BYE", &basilisk_respond_goodbye },    // disconnect
        
        // gecko chains
        { (void *)"GET", &basilisk_respond_geckoget },      // requests headers, block or tx
        { (void *)"HDR", &basilisk_respond_geckoheaders },  // reports headers
        { (void *)"BLK", &basilisk_respond_geckoblock },    // reports virtchain block
        { (void *)"MEM", &basilisk_respond_mempool },       // reports virtchain mempool
        { (void *)"GTX", &basilisk_respond_geckotx },       // reports virtchain tx
        
        { (void *)"ADD", &basilisk_respond_addrelay },   // relays register with each other bus
        { (void *)"DEX", &basilisk_respond_DEX },
        { (void *)"RID", &basilisk_respond_RID },
        { (void *)"ACC", &basilisk_respond_ACC },
        
        { (void *)"OUT", &basilisk_respond_OUT }, // send MSG to hash/id/num
        { (void *)"MSG", &basilisk_respond_MSG }, // get MSG (hash, id, num)

        // encrypted data for jumblr
        { (void *)"HOP", &basilisk_respond_forward },    // message forwarding
        { (void *)"BOX", &basilisk_respond_mailbox },    // create/send/check mailbox pubkey
        
        // small virtual private network
        { (void *)"VPN", &basilisk_respond_VPNcreate },  // create virtual network's hub via privkey
        { (void *)"ARC", &basilisk_respond_VPNjoin },    // join
        { (void *)"GAB", &basilisk_respond_VPNmessage }, // private message
        { (void *)"SAY", &basilisk_respond_VPNbroadcast }, // broadcast
        { (void *)"EAR", &basilisk_respond_VPNreceive }, // network receive (via poll)
        { (void *)"END", &basilisk_respond_VPNlogout },  // logout
        
        // coin services
        { (void *)"RAW", &basilisk_respond_rawtx },
        { (void *)"VAL", &basilisk_respond_value },
        { (void *)"BAL", &basilisk_respond_balances },
    };
    symbol = "BTCD";
    if ( senderipbits == 0 )
        expand_ipbits(remoteaddr,myinfo->myaddr.myipbits);
    else expand_ipbits(remoteaddr,senderipbits);
    if ( (valsobj= cJSON_Parse((char *)data)) != 0 )
    {
        //printf("MSGVALS.(%s)\n",(char *)data);
        if ( jobj(valsobj,"coin") != 0 )
            coin = iguana_coinfind(jstr(valsobj,"coin"));
        else if ( jobj(valsobj,"symbol") != 0 )
            coin = iguana_coinfind(jstr(valsobj,"symbol"));
        if ( coin != 0 )
        {
            if ( (height= juint(valsobj,"hwm")) > 0 )
            {
                if ( height > addr->height )
                    addr->height = height;
                if ( height > coin->longestchain )
                    coin->longestchain = height;
            }
        }
        if ( strcmp(type,"RET") == 0 )
        {
            basilisk_result(myinfo,remoteaddr,basilisktag,valsobj,data,datalen);
            return;
        }
    }
    else
    {
        printf("unexpected binary packet datalen.%d\n",datalen);
        return;
    }
    for (i=flag=0; i<sizeof(basilisk_services)/sizeof(*basilisk_services); i++) // iguana node
        if ( strcmp((char *)basilisk_services[i][0],type) == 0 )
        {
            flag = 1;
            break;
        }
    if ( flag == 0 )
        return;
    strncpy(CMD,type,3), CMD[3] = cmd[3] = 0;
    if ( isupper((int32_t)CMD[0]) != 0 && isupper((int32_t)CMD[1]) != 0 && isupper((int32_t)CMD[2]) != 0 )
        from_basilisk = 1;
    else from_basilisk = 0;
    origdata = data;
    origlen = datalen;
    for (i=0; i<3; i++)
    {
        CMD[i] = toupper((int32_t)CMD[i]);
        cmd[i] = tolower((int32_t)CMD[i]);
    }
    if ( 1 && strcmp(CMD,"RID") != 0 && strcmp(CMD,"MSG") != 0 )
        printf("MSGPROCESS %s.(%s) tag.%d\n",CMD,(char *)data,basilisktag);
    myinfo->basilisk_busy = 1;
    if ( valsobj != 0 )
    {
        jsonlen = (int32_t)strlen((char *)data) + 1;
        if ( datalen > jsonlen )
            data += jsonlen, datalen -= jsonlen;
        else data = 0, datalen = 0;
        if ( coin == 0 )
            coin = iguana_coinfind("BTCD");
        if ( coin != 0 )
        {
            symbol = coin->symbol;
            coin->basilisk_busy = 1;
        }
        hash = jbits256(valsobj,"hash");
        timeoutmillis = jint(valsobj,"timeout");
        if ( (numrequired= jint(valsobj,"numrequired")) == 0 )
            numrequired = 1;
        if ( senderipbits != 0 )
            expand_ipbits(remoteaddr,senderipbits);
        else remoteaddr[0] = 0;
        for (i=0; i<sizeof(basilisk_services)/sizeof(*basilisk_services); i++) // iguana node
        {
            if ( strcmp((char *)basilisk_services[i][0],type) == 0 )
            {
                if ( coin->RELAYNODE != 0 ) // iguana node
                {
                    //printf("services %s\n",type);
                    if ( (retstr= (*basilisk_services[i][1])(myinfo,type,addr,remoteaddr,basilisktag,valsobj,data,datalen,hash,from_basilisk)) != 0 )
                    {
                        //printf("from_basilisk.%d ret.(%s)\n",from_basilisk,retstr);
                        //if ( from_basilisk != 0 || strcmp(CMD,"GET") == 0 )
                            basilisk_sendback(myinfo,CMD,symbol,remoteaddr,basilisktag,retstr);
                        if ( retstr != 0 )
                            free(retstr);
                        break;
                    } else printf("services null return\n");
                } else printf("non-relay got unexpected.(%s)\n",type);
            }
        }
        free_json(valsobj);
    }
    if ( coin != 0 )
        coin->basilisk_busy = 0;
    myinfo->basilisk_busy = 0;
}

void basilisk_p2p(void *_myinfo,void *_addr,char *senderip,uint8_t *data,int32_t datalen,char *type,int32_t encrypted)
{
    uint32_t ipbits,basilisktag; int32_t msglen,len=0; void *ptr = 0; uint8_t space[4096]; bits256 senderpub; struct supernet_info *myinfo = _myinfo;
    if ( encrypted != 0 )
    {
        printf("encrypted p2p\n");
        memset(senderpub.bytes,0,sizeof(senderpub));
        if ( (data= SuperNET_deciphercalc(&ptr,&msglen,myinfo->privkey,senderpub,data,datalen,space,sizeof(space))) == 0 )
        {
            printf("basilisk_p2p decrytion error\n");
            return;
        } else datalen = msglen;
    }
    if ( senderip != 0 && senderip[0] != 0 && strcmp(senderip,"127.0.0.1") != 0 )
        ipbits = (uint32_t)calc_ipbits(senderip);
    else ipbits = myinfo->myaddr.myipbits;
    if ( type[0] == 'P' && type[1] == 'I' && type[2] == 'N' )
    {
        if ( strcmp(type,"PIN") == 0 && myinfo->RELAYID >= 0 )
        {
            basilisk_ping_process(myinfo,_addr,ipbits,data,datalen);
        }
    }
    else
    {
        len += iguana_rwnum(0,data,sizeof(basilisktag),&basilisktag);
        //int32_t i; for (i=0; i<datalen-len; i++)
        //    printf("%02x",data[len+i]);
        //printf(" ->received.%d basilisk_p2p.(%s) from %s tag.%d\n",datalen,type,senderip!=0?senderip:"?",basilisktag);
        basilisk_msgprocess(myinfo,_addr,ipbits,type,basilisktag,&data[len],datalen - len);
    }
    if ( ptr != 0 )
        free(ptr);
}

void basilisk_requests_poll(struct supernet_info *myinfo)
{
    char *retstr; cJSON *outerarray; int32_t i,n; struct basilisk_request issueR; double hwm = 0.;
    memset(&issueR,0,sizeof(issueR));
    if ( (retstr= InstantDEX_incoming(myinfo,0,0,0,0)) != 0 )
    {
        //printf("poll.(%s)\n",retstr);
        if ( (outerarray= cJSON_Parse(retstr)) != 0 )
        {
            if ( is_cJSON_Array(outerarray) != 0 )
            {
                n = cJSON_GetArraySize(outerarray);
                for (i=0; i<n; i++)
                    hwm = basilisk_process_results(myinfo,&issueR,jitem(outerarray,i),hwm);
            } else hwm = basilisk_process_results(myinfo,&issueR,outerarray,hwm);
            free_json(outerarray);
        }
        free(retstr);
    }
    if ( hwm > 0. )
    {
        if ( bits256_cmp(myinfo->myaddr.persistent,issueR.hash) == 0 ) // my request
        {
            printf("my req hwm %f\n",hwm);
            if ( (retstr= InstantDEX_accept(myinfo,0,0,0,issueR.requestid,issueR.quoteid)) != 0 )
                free(retstr);
            if ( (retstr= basilisk_start(myinfo,&issueR,1)) != 0 )
                free(retstr);
        }
        else //if ( issueR.quoteid == 0 )
        {
            printf("other req hwm %f\n",hwm);
            issueR.quoteid = basilisk_quoteid(&issueR);
            issueR.desthash = myinfo->myaddr.persistent;
            if ( (retstr= basilisk_start(myinfo,&issueR,0)) != 0 )
                free(retstr);
        } //else printf("basilisk_requests_poll unexpected hwm issueR\n");
    }
}

void basilisks_loop(void *arg)
{
    struct iguana_info *virt,*tmpcoin,*coin,*btcd; struct basilisk_message *msg,*tmpmsg; struct basilisk_item *tmp,*pending; uint32_t now; int32_t i,iter,maxmillis,flag=0; struct supernet_info *myinfo = arg;
    iter = 0;
    while ( 1 )
    {
        portable_mutex_lock(&myinfo->basilisk_mutex);
        HASH_ITER(hh,myinfo->basilisks.issued,pending,tmp)
        {
            if ( pending != 0 && (pending->finished != 0 || OS_milliseconds() > pending->expiration+60000) )
            {
                //printf("enable free for HASH_DELETE.(%p)\n",pending);
                HASH_DELETE(hh,myinfo->basilisks.issued,pending);
                memset(pending,0,sizeof(*pending));
                free(pending);
            }
        }
        portable_mutex_unlock(&myinfo->basilisk_mutex);
        //if ( myinfo->allcoins_numvirts > 0 )
        if ( (btcd= iguana_coinfind("BTCD")) != 0 )
        {
            maxmillis = (1000 / (myinfo->allcoins_numvirts + 1)) + 1;
            //portable_mutex_lock(&myinfo->allcoins_mutex);
            HASH_ITER(hh,myinfo->allcoins,virt,tmpcoin)
            {
                if ( virt->started != 0 && virt->active != 0 && virt->virtualchain != 0 )
                {
                    gecko_iteration(myinfo,btcd,virt,maxmillis), flag++;
                }
            }
            //printf("my RELAYID.%d\n",myinfo->RELAYID);
            //portable_mutex_unlock(&myinfo->allcoins_mutex);
            if ( (rand() % 100) == 0 && myinfo->RELAYID >= 0 )
                basilisk_ping_send(myinfo,btcd);
        }
        HASH_ITER(hh,myinfo->allcoins,coin,tmpcoin)
        {
            //if ( coin->RELAYNODE == 0 && coin->VALIDATENODE == 0 )
            {
                for (i=0; i<BASILISK_MAXRELAYS; i++)
                    if ( coin->relay_RTheights[i] != 0 )
                        break;
                if ( i == BASILISK_MAXRELAYS || (time(NULL) % 60) == 0 )
                    basilisk_unspents_update(myinfo,coin);
            }
        }
        //if ( (myinfo->RELAYID >= 0 || time(NULL) < myinfo->DEXactive) )
            basilisk_requests_poll(myinfo);
        now = (uint32_t)time(NULL);
        portable_mutex_lock(&myinfo->messagemutex);
        HASH_ITER(hh,myinfo->messagetable,msg,tmpmsg)
        {
            if ( now > msg->expiration )
            {
                printf("delete expired message.%p\n",msg);
                HASH_DELETE(hh,myinfo->messagetable,msg);
                free(msg);
            }
        }
        portable_mutex_unlock(&myinfo->messagemutex);
        if ( myinfo->RELAYID >= 0 )
            usleep(100000);
        else sleep(1);
    }
}

void basilisks_init(struct supernet_info *myinfo)
{
    iguana_initQ(&myinfo->msgQ,"messageQ");
    portable_mutex_init(&myinfo->bu_mutex);
    portable_mutex_init(&myinfo->allcoins_mutex);
    portable_mutex_init(&myinfo->basilisk_mutex);
    portable_mutex_init(&myinfo->DEX_mutex);
    portable_mutex_init(&myinfo->DEX_swapmutex);
    portable_mutex_init(&myinfo->DEX_reqmutex);
    portable_mutex_init(&myinfo->gecko_mutex);
    portable_mutex_init(&myinfo->messagemutex);
    myinfo->basilisks.launched = iguana_launch(iguana_coinfind("BTCD"),"basilisks_loop",basilisks_loop,myinfo,IGUANA_PERMTHREAD);
}
