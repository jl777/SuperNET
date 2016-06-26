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

//typedef char *basilisk_coinfunc(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen);
typedef char *basilisk_servicefunc(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk);
//typedef struct basilisk_item *basilisk_requestfunc(struct basilisk_item *Lptr,struct supernet_info *myinfo,bits256 hash,cJSON *valsobj,uint8_t *data,int32_t datalen);

uint32_t basilisk_calcnonce(struct supernet_info *myinfo,uint8_t *data,int32_t datalen,uint32_t nBits)
{
    int32_t i,numiters = 0; bits256 hash,hash2,threshold; uint32_t basilisktag;
    vcalc_sha256(0,hash.bytes,data,datalen);
    threshold = bits256_from_compact(nBits);
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
    char *sendstr,*hexstr=0; uint8_t *data,hexspace[8192],*allocptr=0,*hexdata; int32_t datalen,hexlen=0;
    if ( jobj(sendjson,"symbol") == 0 )
        jaddstr(sendjson,"symbol",symbol);
    if ( (hexstr= jstr(sendjson,"data")) != 0 )
    {
        hexdata = get_dataptr(0,&allocptr,&hexlen,hexspace,sizeof(hexspace),hexstr);
        //printf("delete data.%s from sendjson\n",hexstr);
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
        else if ( strcmp(destipaddr,"127.0.0.1") == 0 )
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
    r = rand();
    //portable_mutex_lock(&myinfo->allcoins_mutex);
    HASH_ITER(hh,myinfo->allcoins,coin,tmp)
    {
        if (  coin->peers == 0 )
            continue;
        if ( coin->RELAYNODE == 0 && coin->VALIDATENODE == 0 )
            cmd[0] = 's';
        else cmd[0] = 'S';
        for (l=0; l<IGUANA_MAXPEERS; l++)
        {
            i = (l + r) % IGUANA_MAXPEERS;
            addr = &coin->peers->active[i];
            if ( addr->usock >= 0 )
            {
                for (s=0; s<n; s++)
                    if ( alreadysent[s] == addr->ipbits )
                        break;
                //printf("%s s.%d vs n.%d\n",addr->ipaddr,s,n);
                if ( s == n && (addr->supernet != 0 || addr->basilisk != 0) && (destipaddr == 0 || strcmp(addr->ipaddr,destipaddr) == 0) )
                {
                    //printf("[%s].tag%d send %s.(%s) [%x] datalen.%d addr->supernet.%u basilisk.%u to (%s).%d destip.%s\n",cmd,*(uint32_t *)data,type,(char *)&data[4],*(int32_t *)&data[datalen-4],datalen,addr->supernet,addr->basilisk,addr->ipaddr,addr->A.port,destipaddr!=0?destipaddr:"broadcast");
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

void basilisk_p2p(void *_myinfo,void *_addr,char *senderip,uint8_t *data,int32_t datalen,char *type,int32_t encrypted)
{
    uint32_t ipbits,basilisktag; int32_t msglen,len=0; void *ptr = 0; uint8_t space[8192]; bits256 senderpub; struct supernet_info *myinfo = _myinfo;
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
    else ipbits = 0;
    len += iguana_rwnum(0,data,sizeof(basilisktag),&basilisktag);
    //int32_t i; for (i=0; i<datalen-len; i++)
    //    printf("%02x",data[len+i]);
    printf(" ->received.%d basilisk_p2p.(%s) from %s tag.%d\n",datalen,type,senderip!=0?senderip:"?",basilisktag);
    basilisk_msgprocess(myinfo,_addr,ipbits,type,basilisktag,&data[len],datalen - len);
    if ( ptr != 0 )
        free(ptr);
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

struct basilisk_item *basilisk_issueremote(struct supernet_info *myinfo,int32_t *numsentp,char *CMD,char *symbol,int32_t blockflag,cJSON *valsobj,int32_t fanout,int32_t minresults,uint32_t basilisktag,int32_t timeoutmillis,void *_metricfunc,char *retstr,int32_t encryptflag,int32_t delaymillis,uint32_t nBits)
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
        data = basilisk_jsondata(sizeof(struct iguana_msghdr),&allocptr,space,sizeof(space),&datalen,symbol,valsobj,basilisktag);
        *numsentp = pending->numsent = basilisk_sendcmd(myinfo,0,CMD,&pending->basilisktag,encryptflag,delaymillis,data,datalen,1,pending->nBits);
        if ( blockflag != 0 )
        {
            portable_mutex_lock(&myinfo->basilisk_mutex);
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
                //if ( (retstr= basilisk_iscomplete(ptr)) != 0 )
                if ( pending->numresults >= pending->numrequired || (retstr= pending->retstr) != 0 )
                    break;
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

struct basilisk_item *basilisk_requestservice(struct supernet_info *myinfo,char *CMD,int32_t blockflag,cJSON *valsobj,bits256 hash,uint8_t *data,int32_t datalen,uint32_t nBits)
{
    int32_t minresults,timeoutmillis,numsent,delaymillis,encryptflag,fanout; struct basilisk_item *ptr; char buf[4096],*symbol,*str = 0; struct iguana_info *virt;
    //if ( (btcd= iguana_coinfind("BTCD")) != 0 && btcd->RELAYNODE != 0 )
    //    jaddnum(valsobj,"iamrelay",1);
    basilisk_addhexstr(&str,valsobj,buf,sizeof(buf),data,datalen);
    if ( bits256_cmp(hash,GENESIS_PUBKEY) != 0 && bits256_nonz(hash) != 0 )
    {
        if ( jobj(valsobj,"hash") != 0 )
            jdelete(valsobj,"hash");
        jaddbits256(valsobj,"hash",hash);
    }
    if ( (minresults= jint(valsobj,"minresults")) <= 0 )
        minresults = 1;
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
    ptr = basilisk_issueremote(myinfo,&numsent,CMD,symbol,blockflag,valsobj,fanout,minresults,0,timeoutmillis,0,0,encryptflag,delaymillis,nBits);
    return(ptr);
}

char *basilisk_standardservice(char *CMD,struct supernet_info *myinfo,bits256 hash,cJSON *valsobj,char *hexstr,int32_t blockflag) // client side
{
    uint32_t nBits = 0; uint8_t space[8192],*allocptr=0,*data = 0; struct basilisk_item *ptr; int32_t datalen = 0; cJSON *retjson; char *retstr=0;
    data = get_dataptr(BASILISK_HDROFFSET,&allocptr,&datalen,space,sizeof(space),hexstr);
    ptr = basilisk_requestservice(myinfo,CMD,blockflag,valsobj,hash,data,datalen,nBits);
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
    printf("%s.(%s) -> (%s)\n",CMD,jprint(valsobj,0),retstr!=0?retstr:"");
    return(retstr);
}

#include "basilisk_bitcoin.c"
#include "basilisk_nxt.c"
#include "basilisk_ether.c"
#include "basilisk_waves.c"
#include "basilisk_lisk.c"
#include "basilisk_CMD.c"

void basilisk_functions(struct iguana_info *coin,int32_t protocol)
{
    coin->protocol = protocol;
    switch ( protocol )
    {
        case IGUANA_PROTOCOL_BITCOIN:
            coin->basilisk_balances = basilisk_bitcoinbalances;
            coin->basilisk_rawtx = basilisk_bitcoinrawtx;
            //coin->basilisk_rawtxmetric = basilisk_bitcoin_rawtxmetric;
            coin->basilisk_value = basilisk_bitcoinvalue;
            coin->basilisk_valuemetric = basilisk_bitcoin_valuemetric;
            break;
        /*case IGUANA_PROTOCOL_IOTA:
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
    bits256 hash; uint8_t *serialized; int32_t i,len = 0; char *str=0,*retstr,*hexstr,*allocptr=0,space[8192]; bits256 txid; cJSON *vals;
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
            if ( (retstr= basilisk_standardservice(CMD,myinfo,hash,vals,hexstr,0)) != 0 )
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
        printf("(%s) -> Q.%u results vals.(%s)\n",CMD,basilisktag,retstr);
        if ( strcmp(CMD,"GET") == 0 )
            basilisk_geckoresult(myinfo,remoteaddr,retstr,data,datalen);
        else
        {
            portable_mutex_lock(&myinfo->basilisk_mutex);
            HASH_FIND(hh,myinfo->basilisks.issued,&basilisktag,sizeof(basilisktag),pending);
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

int32_t baslisk_relay_report(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen,struct basilisk_relaystatus *reported,uint8_t pingdelay)
{
    if ( reported != 0 )
    {
        reported->pingdelay = pingdelay;
    }
    return(0);
}

int32_t basilisk_relay_ping(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen,struct basilisk_relay *rp)
{
    int32_t datalen = 0;
    datalen = iguana_rwnum(1,&data[datalen],sizeof(rp->ipbits),&rp->ipbits);
    data[datalen++] = rp->direct.pingdelay;
    return(datalen);
}

int32_t basilisk_relay_unping(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen,struct basilisk_relay *rp,int32_t i)
{
    uint8_t pingdelay; int32_t j,datalen = 0; uint32_t ipbits;
    if ( maxlen < sizeof(ipbits)+1 )
    {
        printf("unping error maxlen.%d is too small\n",maxlen);
        return(-1);
    }
    datalen = iguana_rwnum(1,&data[datalen],sizeof(ipbits),&ipbits);
    pingdelay = data[datalen++];
    if ( myinfo->relays[i].ipbits != ipbits )
        printf("unping warning reported.[%d] ipbits %u != %u\n",i,myinfo->relays[i].ipbits,ipbits);
    for (j=0; j<myinfo->numrelays; j++)
        if ( myinfo->relays[j].ipbits == ipbits )
        {
            datalen += baslisk_relay_report(myinfo,&data[datalen],maxlen-datalen,&rp->reported[j],pingdelay);
            return(datalen);
        }
    datalen += baslisk_relay_report(myinfo,&data[datalen],maxlen-datalen,0,pingdelay);
    return(datalen);
}

int32_t basilisk_relays_ping(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen)
{
    int32_t i,datalen = 0;
    data[datalen++] = myinfo->numrelays;
    for (i=0; i<myinfo->numrelays; i++)
        datalen += basilisk_relay_ping(myinfo,&data[datalen],maxlen - datalen,&myinfo->relays[i]);
    for (i=0; i<datalen; i++)
        printf("%02x",data[i]);
    printf(" <- output ping\n");
    return(datalen);
}

void basilisk_respond_ping(struct supernet_info *myinfo,char *remoteaddr,uint8_t *data,int32_t datalen)
{
    int32_t diff,n,len = 0; char ipbuf[64]; struct basilisk_relay *rp; uint8_t numrelays; uint32_t i,ipbits,now = (uint32_t)time(NULL);
    if ( remoteaddr == 0 || remoteaddr[0] == 0 || strcmp("127.0.0.1",remoteaddr) == 0 )
        ipbits = myinfo->myaddr.myipbits;
    else ipbits = (uint32_t)calc_ipbits(remoteaddr);
    expand_ipbits(ipbuf,ipbits);
    for (i=0; i<datalen; i++)
        printf("%02x",data[i]);
    printf(" <- input ping from.(%s)\n",ipbuf);
    for (i=0; i<myinfo->numrelays; i++)
    {
        rp = &myinfo->relays[i];
        rp->direct.pingdelay = 0;
        if ( rp->ipbits == ipbits )
            rp->lastping = now;
        if ( rp->lastping == now )
            rp->direct.pingdelay = 1;
        else
        {
            diff = (now - rp->lastping);
            if ( diff < 0xff )
                rp->direct.pingdelay = diff;
        }
    }
    numrelays = data[len++];
    for (i=0; i<numrelays; i++)
    {
        if ( len > datalen )
            break;
        if ( (n= basilisk_relay_unping(myinfo,&data[len],datalen-len,rp,i)) < 0 )
            break;
        len += n;
    }
    printf("PING got %d, processed.%d from (%s)\n",datalen,len,remoteaddr!=0?remoteaddr:"");
}

void basilisk_msgprocess(struct supernet_info *myinfo,void *_addr,uint32_t senderipbits,char *type,uint32_t basilisktag,uint8_t *data,int32_t datalen)
{
    cJSON *valsobj; char *symbol,*retstr=0,remoteaddr[64],CMD[4],cmd[4]; int32_t height,origlen,from_basilisk,i,timeoutmillis,flag,numrequired,jsonlen; uint8_t *origdata; struct iguana_info *coin=0; bits256 hash; struct iguana_peer *addr = _addr;
    static basilisk_servicefunc *basilisk_services[][2] =
    {
        { (void *)"BYE", &basilisk_respond_goodbye },    // disconnect
        
        // gecko chains
        //{ (void *)"NEW", &basilisk_respond_newgeckochain }, // creates new virtual gecko chain
        ///{ (void *)"GEN", &basilisk_respond_geckogenesis },  // returns genesis list
        { (void *)"GET", &basilisk_respond_geckoget },      // requests headers, block or tx
        { (void *)"HDR", &basilisk_respond_geckoheaders },  // reports headers
        { (void *)"BLK", &basilisk_respond_geckoblock },    // reports block
        { (void *)"MEM", &basilisk_respond_mempool },       // reports mempool
        { (void *)"GTX", &basilisk_respond_geckotx },       // reports tx
        //{ (void *)"SEQ", &basilisk_respond_hashstamps }, // BTCD and BTC recent hashes from timestamp
        
        // unencrypted low level functions, used by higher level protocols and virtual network funcs
        { (void *)"ADD", &basilisk_respond_addrelay },   // relays register with each other bus
        //{ (void *)"RLY", &basilisk_respond_relays },
        { (void *)"DEX", &basilisk_respond_instantdex },
        
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
        if ( strcmp(type,"PIN") == 0 && myinfo->RELAYID >= 0 )
        {
            basilisk_respond_ping(myinfo,remoteaddr,data,datalen);
        }
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
    printf("MSGPROCESS.(%s) tag.%d\n",(char *)data,basilisktag);
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
                    if ( (retstr= (*basilisk_services[i][1])(myinfo,type,addr,remoteaddr,basilisktag,valsobj,data,datalen,hash,from_basilisk)) != 0 )
                    {
                        //printf("from_basilisk.%d ret.(%s)\n",from_basilisk,retstr);
                        //if ( from_basilisk != 0 || strcmp(CMD,"GET") == 0 )
                            basilisk_sendback(myinfo,CMD,symbol,remoteaddr,basilisktag,retstr);
                        if ( retstr != 0 )
                            free(retstr);
                        break;
                    } //else printf("services null return\n");
                } else printf("non-relay got unexpected.(%s)\n",type);
            }
        }
        free_json(valsobj);
    }
    if ( coin != 0 )
        coin->basilisk_busy = 0;
    myinfo->basilisk_busy = 0;
}

void basilisks_loop(void *arg)
{
    struct iguana_info *virt,*tmpcoin,*btcd; struct basilisk_item *tmp,*pending; int32_t iter,maxmillis,flag=0; struct supernet_info *myinfo = arg;
    iter = 0;
    while ( 1 )
    {
        portable_mutex_lock(&myinfo->basilisk_mutex);
        HASH_ITER(hh,myinfo->basilisks.issued,pending,tmp)
        {
            if ( pending != 0 && (pending->finished != 0 || OS_milliseconds() > pending->expiration+60) )
            {
                HASH_DELETE(hh,myinfo->basilisks.issued,pending);
                free(pending);
            }
        }
        portable_mutex_unlock(&myinfo->basilisk_mutex);
        //if ( myinfo->allcoins_numvirts > 0 )
        if ( (btcd= iguana_coinfind("BTCD")) != 0 )
        {
            maxmillis = (10000 / (myinfo->allcoins_numvirts + 1)) + 1;
            //portable_mutex_lock(&myinfo->allcoins_mutex);
            HASH_ITER(hh,myinfo->allcoins,virt,tmpcoin)
            {
                if ( virt->started != 0 && virt->active != 0 && virt->virtualchain != 0 )
                {
                    gecko_iteration(myinfo,btcd,virt,maxmillis), flag++;
                }
            }
            //portable_mutex_unlock(&myinfo->allcoins_mutex);
            if ( (rand() % 10) == 0 && myinfo->RELAYID >= 0 )
            {
                struct iguana_peer *addr; struct basilisk_relay *rp; int32_t i,datalen=0; uint8_t data[32768];
                datalen = basilisk_relays_ping(myinfo,&data[sizeof(struct iguana_msghdr)],sizeof(data)-sizeof(struct iguana_msghdr));
                for (i=0; i<myinfo->numrelays; i++)
                {
                    rp = &myinfo->relays[i];
                    addr = 0;
                    if ( rp->ipbits == myinfo->myaddr.myipbits )
                        basilisk_msgprocess(myinfo,0,0,"PIN",0,&data[sizeof(struct iguana_msghdr)],datalen);
                    else if ( (addr= iguana_peerfindipbits(btcd,rp->ipbits,1)) != 0 && addr->usock >= 0 )
                    {
                        if ( iguana_queue_send(addr,0,&data[sizeof(struct iguana_msghdr)],"SuperNETPIN",datalen) <= 0 )
                            printf("error sending %d to (%s)\n",datalen,addr->ipaddr);
                        else printf("sent %d to (%s)\n",datalen,addr->ipaddr);
                    }
                }
            }
        }
        //fprintf(stderr,"i ");
        //for (i=0; i<IGUANA_MAXCOINS; i++)
        //    if ( (coin= Coins[i]) != 0 && coin->RELAYNODE == 0 && coin->VALIDATENODE == 0 && coin->active != 0 && coin->chain->userpass[0] != 0 && coin->MAXPEERS == 1 )
        //        basilisk_bitcoinscan(coin,blockspace,&RAWMEM);
        usleep(100000);
    }
}

void basilisks_init(struct supernet_info *myinfo)
{
    //iguana_initQ(&myinfo->basilisks.submitQ,"submitQ");
    //iguana_initQ(&myinfo->basilisks.resultsQ,"resultsQ");
    portable_mutex_init(&myinfo->allcoins_mutex);
    portable_mutex_init(&myinfo->basilisk_mutex);
    portable_mutex_init(&myinfo->gecko_mutex);
    myinfo->basilisks.launched = iguana_launch(iguana_coinfind("BTCD"),"basilisks_loop",basilisks_loop,myinfo,IGUANA_PERMTHREAD);
}
