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

uint32_t basilisk_majority32(int32_t *datalenp,uint32_t rawcrcs[64],int32_t datalens[64],int32_t numcrcs)
{
    int32_t tally[64],candlens[64],i,j,mintally,numcandidates = 0; uint32_t candidates[64];
    *datalenp = 0;
    mintally = (numcrcs >> 1) + 1;
    memset(tally,0,sizeof(tally));
    memset(candlens,0,sizeof(candlens));
    memset(candidates,0,sizeof(candidates));
    if ( numcrcs > 0 )
    {
        for (i=0; i<numcrcs; i++)
        {
            //printf("%08x ",rawcrcs[i]);
            for (j=0; j<numcandidates; j++)
            {
                if ( rawcrcs[i] == candidates[j] && datalens[i] == candlens[j] )
                {
                    tally[j]++;
                    break;
                }
            }
            if ( j == numcandidates )
            {
                tally[numcandidates] = 1;
                candlens[numcandidates] = datalens[i];
                candidates[numcandidates] = rawcrcs[i];
                numcandidates++;
            }
        }
        //printf("n.%d -> numcandidates.%d\n",i,numcandidates);
        if ( numcandidates > 0 )
        {
            for (j=0; j<numcandidates; j++)
                if ( tally[j] >= mintally )
                {
                    *datalenp = candlens[j];
                    //printf("tally[%d] %d >= mintally.%d numcrcs.%d crc %08x datalen.%d\n",j,tally[j],mintally,numcrcs,candidates[j],*datalenp);
                    return(candidates[j]);
                }
        }
    }
    return(0);
}

int32_t basilisk_notarycmd(char *cmd)
{
    //&& strcmp(cmd,"DEX") != 0 && strcmp(cmd,"ACC") != 0 && strcmp(cmd,"RID") != 0 &&
    if ( strcmp(cmd,"PIN") != 0 && strcmp(cmd,"OUT") != 0 && strcmp(cmd,"MSG") != 0 && strcmp(cmd,"VOT") != 0 )
        return(0);
    else return(1);
}

/*int32_t basilisk_specialrelay_CMD(char *CMD)
{
    if ( strcmp(CMD,"OUT") == 0 || strcmp(CMD,"MSG") == 0 || strcmp(CMD,"BLK") == 0 || strcmp(CMD,"MEM") == 0 || strcmp(CMD,"GTX") == 0 || strcmp(CMD,"RID") == 0 )
        return(1);
    else return(0);
}*/

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
    iguana_rwnum(1,&data[-(int32_t)sizeof(basilisktag)],sizeof(basilisktag),&basilisktag);
    //char str[65],str2[65]; printf("found hash after numiters.%d %s vs %s basilisktag.%u\n",numiters,bits256_str(str,threshold),bits256_str(str2,hash2),basilisktag);
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
    char *sendstr,*hexstr=0; uint8_t *data,hexspace[4096],*allocptr=0,*hexdata=0; int32_t datalen,hexlen=0;
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
    if ( hexlen > 0 && hexdata != 0 )
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

struct basilisk_item *basilisk_itemcreate(struct supernet_info *myinfo,char *CMD,char *symbol,uint32_t basilisktag,int32_t numrequired,cJSON *vals,int32_t timeoutmillis,void *metricfunc)
{
    struct basilisk_item *ptr;
    ptr = calloc(1,sizeof(*ptr));
    ptr->basilisktag = basilisktag;
    if ( (ptr->numrequired= numrequired) == 0 )
        ptr->numrequired = 1;
    strcpy(ptr->CMD,CMD);
    safecopy(ptr->symbol,symbol,sizeof(ptr->symbol));
    ptr->duration = timeoutmillis;
    ptr->expiration = OS_milliseconds() + timeoutmillis;
    //printf("itemcreate.%p %s %f timeout.%d\n",ptr,CMD,OS_milliseconds(),timeoutmillis);
    return(ptr);
}

int32_t basilisk_sendcmd(struct supernet_info *myinfo,char *destipaddr,char *type,uint32_t *basilisktagp,int32_t encryptflag,int32_t delaymillis,uint8_t *data,int32_t datalen,int32_t fanout,uint32_t nBits) // data must be offset by sizeof(iguana_msghdr)+sizeof(basilisktag)
{
    int32_t i,l,s,valid,val,n=0,retval = -1; char cmd[12]; struct iguana_info *coin,*tmp; struct iguana_peer *addr; bits256 hash; uint32_t *alreadysent,r;
    if ( fanout <= 0 )
        fanout = sqrt(myinfo->NOTARY.NUMRELAYS) + 1;
    else if ( fanout > BASILISK_MAXFANOUT )
        fanout = BASILISK_MAXFANOUT;
    if ( type == 0 )
        type = "INF";
    if ( strlen(type) > 3 )
    {
        printf("basilisk_sendcmd illegal type(%s)\n",type);
        return(-1);
    }
    if ( destipaddr != 0 )
    {
        if ( destipaddr[0] == 0 )
        {
            destipaddr = 0; // broadcast
        }
        else if ( strcmp(destipaddr,"127.0.0.1") == 0 || strcmp(destipaddr,myinfo->ipaddr) == 0 )
        {
            printf("return after locally basilisk_msgprocess\n");
            hash = GENESIS_PUBKEY;
            basilisk_msgprocess(myinfo,0,0,type,*basilisktagp,data,datalen);
            return(0);
        }
    }
    iguana_rwnum(1,&data[-(int32_t)sizeof(*basilisktagp)],sizeof(*basilisktagp),basilisktagp);
    if ( *basilisktagp == 0 )
    {
        if ( nBits != 0 )
            *basilisktagp = basilisk_calcnonce(myinfo,data,datalen,nBits);
        else *basilisktagp = rand();
        iguana_rwnum(1,&data[-(int32_t)sizeof(*basilisktagp)],sizeof(*basilisktagp),basilisktagp);
    }
    data -= sizeof(*basilisktagp), datalen += sizeof(*basilisktagp);
    memset(cmd,0,sizeof(cmd));
    sprintf(cmd,"SuperNET%s",type);
    if ( destipaddr != 0 )
    {
        cmd[6] = 'E', cmd[7] = 'T';
        HASH_ITER(hh,myinfo->allcoins,coin,tmp)
        {
            if (  coin->peers == 0 )
                continue;
            if ( coin->FULLNODE == 0 && coin->VALIDATENODE == 0 )
                cmd[0] = 's';
            else cmd[0] = 'S';
            for (i=0; i<IGUANA_MAXPEERS; i++)
            {
                addr = &coin->peers->active[i];
                if ( addr->usock >= 0 && strcmp(addr->ipaddr,destipaddr) == 0 )
                {
                    return(iguana_queue_send(addr,delaymillis,&data[-(int32_t)sizeof(struct iguana_msghdr)],cmd,datalen));
                }
            }
        }
        return(-1);
    }
    if ( basilisk_notarycmd(type) != 0 && myinfo->NOTARY.NUMRELAYS == 0 )
    {
        printf("no notary nodes to send (%s) to\n",type);
        return(-1);
    }
    //portable_mutex_lock(&myinfo->allcoins_mutex);
    alreadysent = calloc(IGUANA_MAXPEERS * IGUANA_MAXCOINS,sizeof(*alreadysent));
    HASH_ITER(hh,myinfo->allcoins,coin,tmp)
    {
        if (  coin->peers == 0 )
            continue;
        if ( basilisk_notarycmd(type) != 0 && strcmp(coin->symbol,"NOTARY") != 0 )
            continue;
        if ( coin->FULLNODE == 0 && coin->VALIDATENODE == 0 )
            cmd[0] = 's';
        else cmd[0] = 'S';
        r = rand() % IGUANA_MAXPEERS;
        for (l=0; l<IGUANA_MAXPEERS; l++)
        {
            i = (l + r) % IGUANA_MAXPEERS;
            addr = &coin->peers->active[i];
            if ( addr->supernet != 0 || addr->basilisk != 0 )
                valid = 1;
            else valid = 0;
            if ( addr->usock >= 0 )
            {
                s = 0;
                valid = (addr->supernet != 0);
                if ( basilisk_notarycmd(type) != 0 || (strcmp(type,"INF") == 0 && strcmp(coin->symbol,"NOTARY") == 0) )
                {
                    valid = 0;
                    /*OS_randombytes((void *)&r2,sizeof(r2));
                    if ( (r2 % myinfo->NOTARY.NUMRELAYS) >= sqrt(myinfo->NOTARY.NUMRELAYS) )
                    {
                        printf("fanout.%d s.%d n.%d skip %s\n",fanout,s,n,addr->ipaddr);
                        continue;
                    }*/
                    for (s=0; s<myinfo->NOTARY.NUMRELAYS; s++)
                        if ( addr->ipbits != myinfo->myaddr.myipbits && myinfo->NOTARY.RELAYS[s].ipbits == addr->ipbits )
                            break;
                    if ( s == myinfo->NOTARY.NUMRELAYS )
                    {
                        //printf("skip non-relay.(%s)\n",addr->ipaddr);
                        continue;
                    }
                    valid = 1;
                    //printf("send to other relay.(%s)\n",addr->ipaddr);
                }
                for (s=0; s<n; s++)
                    if ( alreadysent[s] == addr->ipbits )
                    {
                        //printf("already sent to %s\n",addr->ipaddr);
                        continue;
                    }
                if ( s == n && valid == 1 && (destipaddr == 0 || strcmp(addr->ipaddr,destipaddr) == 0) )
                {
                    //fprintf(stderr,">>> (%s).%u ",addr->ipaddr,coin->chain->portp2p);
                    //printf("n.%d/fanout.%d i.%d l.%d [%s].tag%u send %s [%x] datalen.%d addr->supernet.%u basilisk.%u to (%s).%d destip.%s\n",n,fanout,i,l,cmd,*(uint32_t *)data,type,*(int32_t *)&data[datalen-4],datalen,addr->supernet,addr->basilisk,addr->ipaddr,addr->A.port,destipaddr!=0?destipaddr:"broadcast");
                    if ( encryptflag != 0 && bits256_nonz(addr->pubkey) != 0 )
                    {
                        void *ptr; uint8_t *cipher,space[8192]; int32_t cipherlen; bits256 privkey;
                        cmd[6] = 'e', cmd[7] = 't';
                        memset(privkey.bytes,0,sizeof(privkey));
                        if ( (cipher= SuperNET_ciphercalc(&ptr,&cipherlen,&privkey,&addr->pubkey,data,datalen,space,sizeof(space))) != 0 )
                        {
                            if ( (val= iguana_queue_send(addr,delaymillis,&cipher[-(int32_t)sizeof(struct iguana_msghdr)],cmd,cipherlen)) >= cipherlen )
                                alreadysent[n++] = (uint32_t)addr->ipbits;
                            if ( ptr != 0 )
                                free(ptr);
                        }
                    }
                    else
                    {
                        cmd[6] = 'E', cmd[7] = 'T';
                        if ( (val= iguana_queue_send(addr,delaymillis,&data[-(int32_t)sizeof(struct iguana_msghdr)],cmd,datalen)) >= datalen )
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
            jaddnum(valsobj,"timestamp",(uint32_t)time(NULL));
            if ( (virt= iguana_coinfind(symbol)) != 0 )
            {
                jaddnum(valsobj,"hwm",virt->blocks.hwmchain.height);
                if ( bits256_nonz(virt->blocks.hwmchain.RO.hash2) != 0 )
                    jaddbits256(valsobj,"chaintip",virt->blocks.hwmchain.RO.hash2);
            }
            data = basilisk_jsondata(sizeof(struct iguana_msghdr),&allocptr,space,sizeof(space),&datalen,symbol,valsobj,basilisktag);
            //printf("sendback.%d -> %s\n",datalen,remoteaddr);
            basilisk_sendcmd(myinfo,remoteaddr,"RET",&basilisktag,encryptflag,delaymillis,data,datalen,0,0);
            if ( allocptr != 0 )
                free(allocptr);
            free_json(valsobj);
        }
    }
}

struct basilisk_item *basilisk_issueremote(struct supernet_info *myinfo,struct iguana_peer *addr,int32_t *numsentp,char *CMD,char *symbol,int32_t blockflag,cJSON *valsobj,int32_t fanout,int32_t numrequired,uint32_t basilisktag,int32_t timeoutmillis,void *deprecated_dontuse,char *retstr,int32_t encryptflag,int32_t delaymillis,uint32_t nBits)
{
    struct basilisk_item *pending; uint8_t *allocptr,*data,space[4096]; int32_t datalen;
    pending = basilisk_itemcreate(myinfo,CMD,symbol,basilisktag,numrequired,valsobj,timeoutmillis,0);
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
            HASH_ADD(hh,myinfo->basilisks.issued,basilisktag,sizeof(basilisktag),pending);
            portable_mutex_unlock(&myinfo->basilisk_mutex);
            if ( pending->expiration <= OS_milliseconds() )
                pending->expiration = OS_milliseconds() + pending->duration;
            strcpy(pending->symbol,"NOTARY");
            strcpy(pending->CMD,CMD);
            //printf("block for %f\n",pending->expiration - OS_milliseconds());
            while ( OS_milliseconds() < pending->expiration )
            {
                portable_mutex_lock(&myinfo->basilisk_mutex);
                if ( pending->numresults >= pending->numrequired )
                {
                    portable_mutex_unlock(&myinfo->basilisk_mutex);
                    //printf("%p <<<<<<<<<<<<< numresults.%d vs numrequired.%d\n",pending,pending->numresults,pending->numrequired);
                    break;
                }
                portable_mutex_unlock(&myinfo->basilisk_mutex);
                usleep(10000);
            }
        }
        if ( allocptr != 0 )
            free(allocptr);
    }
    return(pending);
}

struct basilisk_item *basilisk_requestservice(struct supernet_info *myinfo,struct iguana_peer *addr,char *CMD,int32_t blockflag,cJSON *valsobj,bits256 hash,uint8_t *data,int32_t datalen,uint32_t nBits)
{
    int32_t minfanout,numrequired,timeoutmillis,numsent,delaymillis,encryptflag,fanout; struct basilisk_item *ptr; char buf[4096],*symbol,*str = 0; struct iguana_info *virt;
    //printf("request.(%s)\n",jprint(valsobj,0));
    basilisk_addhexstr(&str,valsobj,buf,sizeof(buf),data,datalen);
    if ( str != 0 )
        free(str);
    if ( bits256_nonz(hash) == 0 || (bits256_cmp(hash,GENESIS_PUBKEY) != 0 && bits256_nonz(hash) != 0) )
    {
        if ( jobj(valsobj,"hash") != 0 )
            jdelete(valsobj,"hash");
        jaddbits256(valsobj,"hash",hash);
    }
    if ( (timeoutmillis= jint(valsobj,"timeout")) == 0 )
        timeoutmillis = BASILISK_TIMEOUT;
    minfanout = sqrt(myinfo->NOTARY.NUMRELAYS)+1;
    if ( minfanout < 8 )
        minfanout = 8;
    if ( jobj(valsobj,"fanout") == 0 )
        fanout = minfanout;
    else fanout = jint(valsobj,"fanout");
    if ( fanout < minfanout )
        fanout = minfanout;
    if ( (numrequired= jint(valsobj,"numrequired")) <= 0 )
        numrequired = MIN(fanout/2,sqrt(myinfo->NOTARY.NUMRELAYS)+1);
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
        symbol = "NOTARY";
    encryptflag = jint(valsobj,"encrypt");
    delaymillis = jint(valsobj,"delay");
    ptr = basilisk_issueremote(myinfo,addr,&numsent,CMD,symbol,blockflag,valsobj,fanout,numrequired,0,timeoutmillis,0,0,encryptflag,delaymillis,nBits);
    return(ptr);
}

char *basilisk_standardservice(char *CMD,struct supernet_info *myinfo,void *_addr,bits256 hash,cJSON *valsobj,char *hexstr,int32_t blockflag) // client side
{
    uint32_t nBits = 0; uint8_t space[4096],*allocptr=0,*data = 0; struct basilisk_item *ptr; int32_t i,datalen = 0; cJSON *retjson; char *retstr=0;
    if ( myinfo->IAMNOTARY != 0 && myinfo->NOTARY.RELAYID >= 0 && (strcmp(CMD,"INF") != 0 && basilisk_notarycmd(CMD) == 0) )
        return(clonestr("{\"error\":\"unsupported special relay command\"}"));
    data = get_dataptr(BASILISK_HDROFFSET,&allocptr,&datalen,space,sizeof(space),hexstr);
//printf("request.(%s)\n",jprint(valsobj,0));
    ptr = basilisk_requestservice(myinfo,_addr,CMD,blockflag,valsobj,hash,data,datalen,nBits);
    if ( allocptr != 0 )
        free(allocptr);
    if ( ptr != 0 )
    {
        if ( (retstr= ptr->retstr) != 0 )
            ptr->retstr = 0;
        else
        {
            if ( ptr->numresults > 0 )
            {
                retjson = cJSON_CreateArray();
                for (i=0; i<ptr->numresults; i++)
                    jaddi(retjson,ptr->results[i]), ptr->results[i] = 0;
                //printf("numresults.%d (%p)\n",ptr->numresults,ptr);
            }
            else
            {
                retjson = cJSON_CreateObject();
                if ( ptr->numsent > 0 )
                {
                    //queue_enqueue("submitQ",&myinfo->basilisks.submitQ,&ptr->DL,0);
                    jaddstr(retjson,"result","error");
                    jaddnum(retjson,"packetsize",ptr->numsent);
                } else jaddstr(retjson,"error","didnt find any nodes to send to");
            }
            retstr = jprint(retjson,1);
        }
        ptr->finished = OS_milliseconds() + 10000;
    }
    if ( 0 && strcmp("MSG",CMD) == 0 )
        printf("%s.(%s) -> (%s)\n",CMD,jprint(valsobj,0),retstr!=0?retstr:"");
    return(retstr);
}

int32_t basilisk_relayid(struct supernet_info *myinfo,uint32_t ipbits)
{
    int32_t j;
    for (j=0; j<myinfo->NOTARY.NUMRELAYS; j++)
        if ( myinfo->NOTARY.RELAYS[j].ipbits == ipbits )
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
#include "basilisk_vote.c"
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
    bits256 hash; uint8_t *serialized; int32_t i,len = 0; char *str=0,*retstr,*hexstr,space[4096]; bits256 txid; cJSON *vals;
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
            if ( str != 0 )
                free(str);
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
                    if ( strcmp(type,"HDR") == 0 && virt->virtualchain != 0 )
                        str = gecko_headersarrived(myinfo,virt,remoteaddr,data,datalen,hash2);
                    else if ( strcmp(type,"MEM") == 0 && virt->virtualchain != 0 )
                        str = gecko_mempoolarrived(myinfo,virt,remoteaddr,data,datalen,hash2);
                    else if ( strcmp(type,"BLK") == 0 && virt->virtualchain != 0 )
                        str = gecko_blockarrived(myinfo,virt,remoteaddr,data,datalen,hash2,0);
                    else if ( strcmp(type,"GTX") == 0 && virt->virtualchain != 0 )
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
        //if ( 0 && strcmp("RID",CMD) != 0 )
        //printf("(%s) -> Q.%u results vals.(%s)\n",CMD,basilisktag,retstr);//(int32_t)strlen(retstr));
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
                    if ( jobj(item,"myip") == 0 )
                        jaddstr(item,"myip",remoteaddr);
                    if ( pending->numresults < sizeof(pending->results)/sizeof(*pending->results) )
                    {
                        //printf("%p.(%s).%d\n",pending,jprint(item,0),pending->numresults);
                        pending->results[pending->numresults++] = item;
                    }
                } else printf("couldnt parse.(%s)\n",retstr);
            } //else printf("couldnt find issued.%u\n",basilisktag);
        }
        free(retstr);
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
        { (void *)"OUT", &basilisk_respond_OUT },       // send MSG to hash/id/num
        { (void *)"MSG", &basilisk_respond_MSG },       // get MSG (hash, id, num)
        { (void *)"ADD", &basilisk_respond_addrelay },  // relays register with each other bus
        { (void *)"VOT", &basilisk_respond_VOT },       // VOTE handler for something
        //{ (void *)"PIN", &basilisk_respond_PIN },
        
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
         
        //{ (void *)"DEX", &basilisk_respond_DEX },
        //{ (void *)"RID", &basilisk_respond_RID },
        //{ (void *)"ACC", &basilisk_respond_ACC },
        { (void *)"BYE", &basilisk_respond_goodbye },    // disconnect
        
        // gecko chains
        { (void *)"GET", &basilisk_respond_geckoget },      // requests headers, block or tx
        { (void *)"HDR", &basilisk_respond_geckoheaders },  // reports headers
        { (void *)"BLK", &basilisk_respond_geckoblock },    // reports virtchain block
        { (void *)"MEM", &basilisk_respond_mempool },       // reports virtchain mempool
        { (void *)"GTX", &basilisk_respond_geckotx },       // reports virtchain tx
        
        // coin services
        { (void *)"VAL", &basilisk_respond_value },
        { (void *)"BAL", &basilisk_respond_balances },
        { (void *)"INF", &basilisk_respond_getinfo },
    };
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
    if ( myinfo->IAMNOTARY != 0 )//RELAYID >= 0 )
    {
        if ( basilisk_notarycmd(CMD) == 0 && strcmp(CMD,"INF") != 0 )
            return;
    } else if ( basilisk_notarycmd(CMD) != 0 )
        return;
    symbol = "NOTARY";
    if ( senderipbits == 0 )
        expand_ipbits(remoteaddr,myinfo->myaddr.myipbits);
    else expand_ipbits(remoteaddr,senderipbits);
    if ( (valsobj= cJSON_Parse((char *)data)) != 0 )
    {
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
    myinfo->basilisk_busy = 1;
    if ( valsobj != 0 )
    {
        jsonlen = (int32_t)strlen((char *)data) + 1;
        if ( datalen > jsonlen )
            data += jsonlen, datalen -= jsonlen;
        else data = 0, datalen = 0;
        if ( coin == 0 )
            coin = iguana_coinfind(symbol);
        if ( coin != 0 )
        {
            symbol = coin->symbol;
            coin->basilisk_busy = 1;
        }
        hash = jbits256(valsobj,"hash");
        timeoutmillis = jint(valsobj,"timeout");
        if ( (numrequired= jint(valsobj,"numrequired")) == 0 )
            numrequired = sqrt(myinfo->NOTARY.NUMRELAYS)+1;
        if ( senderipbits != 0 )
            expand_ipbits(remoteaddr,senderipbits);
        else remoteaddr[0] = 0;
        for (i=0; i<sizeof(basilisk_services)/sizeof(*basilisk_services); i++) // iguana node
        {
            if ( strcmp((char *)basilisk_services[i][0],type) == 0 )
            {
                if ( (coin != 0 && coin->FULLNODE > 0) || myinfo->NOTARY.RELAYID >= 0 ) // iguana node
                {
                    //printf("\n call %s from_basilisk.%d (%s)\n",addr->ipaddr,from_basilisk,type);
                    if ( (retstr= (*basilisk_services[i][1])(myinfo,type,addr,remoteaddr,basilisktag,valsobj,data,datalen,hash,from_basilisk)) != 0 )
                    {
                        //printf("%s from_basilisk.%d ret.(%s)\n",addr->ipaddr,from_basilisk,retstr);
                        //if ( from_basilisk != 0 || strcmp(CMD,"GET") == 0 )
                            basilisk_sendback(myinfo,CMD,symbol,remoteaddr,basilisktag,retstr);
                        if ( retstr != 0 )
                            free(retstr);
                        break;
                    } else printf("services null return\n");
                } else printf("non-relay got %s unhandled.(%s)\n",coin!=0?coin->symbol:"",type);
            }
        }
        free_json(valsobj);
    }
    if ( coin != 0 )
        coin->basilisk_busy = 0;
    myinfo->basilisk_busy = 0;
}

int32_t basilisk_p2pQ_process(struct supernet_info *myinfo,int32_t maxiters)
{
    struct basilisk_p2pitem *ptr; char senderip[64]; uint32_t n=0,basilisktag,len;
    while ( n < maxiters && (ptr= queue_dequeue(&myinfo->p2pQ,0)) != 0 )
    {
        len = 0;
        expand_ipbits(senderip,ptr->ipbits);
        if ( ptr->type[0] == 'P' && ptr->type[1] == 'I' && ptr->type[2] == 'N' )
        {
            if ( myinfo->NOTARY.RELAYID >= 0 )
            {
                basilisk_ping_process(myinfo,ptr->addr,ptr->ipbits,ptr->data,ptr->datalen);
            }
        }
        else
        {
            len += iguana_rwnum(0,ptr->data,sizeof(basilisktag),&basilisktag);
            if ( 0 && myinfo->IAMLP == 0 )
                printf("RELAYID.%d ->received.%d basilisk_p2p.(%s) from %s tag.%u\n",myinfo->NOTARY.RELAYID,ptr->datalen,ptr->type,senderip,basilisktag);
            basilisk_msgprocess(myinfo,ptr->addr,ptr->ipbits,ptr->type,basilisktag,&ptr->data[len],ptr->datalen - len);
            if ( 0 && myinfo->IAMLP == 0 )
                printf("processed.%s from %s\n",ptr->type,senderip);
        }
        free(ptr);
        n++;
    }
    return(n);
}

struct basilisk_p2pitem *basilisk_p2pitem_create(struct iguana_info *coin,struct iguana_peer *addr,char *type,uint32_t ipbits,uint8_t *data,int32_t datalen)
{
    struct basilisk_p2pitem *ptr;
    ptr = calloc(1,sizeof(*ptr) + datalen);
    ptr->coin = coin;
    ptr->addr = addr;
    ptr->ipbits = ipbits;
    ptr->datalen = datalen;
    safecopy(ptr->type,type,sizeof(ptr->type));
    memcpy(ptr->data,data,datalen);
    return(ptr);
}

void basilisk_p2p(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,char *senderip,uint8_t *data,int32_t datalen,char *type,int32_t encrypted)
{
    uint32_t ipbits; int32_t msglen; void *ptr = 0; uint8_t space[4096]; bits256 senderpub;
    ipbits = (uint32_t)calc_ipbits(senderip);
    if ( encrypted != 0 )
    {
        printf("encrypted p2p\n");
        memset(senderpub.bytes,0,sizeof(senderpub));
        if ( (data= SuperNET_deciphercalc(&ptr,&msglen,myinfo->privkey,senderpub,data,datalen,space,sizeof(space))) == 0 )
        {
            printf("basilisk_p2p decrytion error\n");
            return;
        } else datalen = msglen;
        if ( ptr != 0 )
            free(ptr);
    }
    if ( senderip != 0 && senderip[0] != 0 && strcmp(senderip,"127.0.0.1") != 0 )
        ipbits = (uint32_t)calc_ipbits(senderip);
    else ipbits = myinfo->myaddr.myipbits;
    ptr = basilisk_p2pitem_create(coin,addr,type,ipbits,data,datalen);
    queue_enqueue("p2pQ",&myinfo->p2pQ,ptr,0);
}

int32_t basilisk_issued_purge(struct supernet_info *myinfo,int32_t timepad)
{
    struct basilisk_item *tmp,*pending; cJSON *item; int32_t i,n = 0; double startmilli = OS_milliseconds();
    portable_mutex_lock(&myinfo->basilisk_mutex);
    HASH_ITER(hh,myinfo->basilisks.issued,pending,tmp)
    {
        if ( pending != 0 && ((pending->finished > 0 && startmilli > pending->finished) || startmilli > pending->expiration+timepad) )
        {
            HASH_DELETE(hh,myinfo->basilisks.issued,pending);
            //printf("%f > %f (%d) clear pending.%p numresults.%d %p\n",startmilli,pending->expiration+timepad,timepad,pending,pending->numresults,pending->retstr);
            for (i=0; i<pending->numresults; i++)
                if ( (item= pending->results[i]) != 0 )
                    free_json(item);
            if ( pending->retstr != 0 )
                free(pending->retstr);
            memset(pending,0,sizeof(*pending));
            free(pending);
            n++;
        }
    }
    portable_mutex_unlock(&myinfo->basilisk_mutex);
    return(n);
}

void basilisk_iteration(struct supernet_info *myinfo)
{
    struct iguana_info *notary; uint32_t now;
    now = (uint32_t)time(NULL);
    notary = iguana_coinfind("NOTARY");
    if ( myinfo->NOTARY.RELAYID >= 0 )
    {
        basilisk_ping_send(myinfo,notary);
        /*if ( notary != 0 )
        {
         struct iguana_info *virt,*tmpcoin; int32_t maxmillis;
            maxmillis = (1000 / (myinfo->allcoins_numvirts + 1)) + 1;
            HASH_ITER(hh,myinfo->allcoins,virt,tmpcoin)
            {
                if ( virt->started != 0 && virt->active != 0 && virt->virtualchain != 0 )
                    gecko_iteration(myinfo,notary,virt,maxmillis), flag++;
            }
        }*/
    }
    /*else
    {
        if ( myinfo->expiration != 0 && (myinfo->IAMLP != 0 || myinfo->DEXactive > now) )
            basilisk_requests_poll(myinfo);
    }*/
}

void basilisks_loop(void *arg)
{
    static uint32_t counter;
    struct supernet_info *myinfo = arg; int32_t iter; double startmilli,endmilli;
    iter = 0;
    while ( 1 )
    {
        startmilli = OS_milliseconds();
        basilisk_issued_purge(myinfo,600000);
        basilisk_iteration(myinfo);
        basilisk_p2pQ_process(myinfo,777);
        if ( myinfo->NOTARY.RELAYID >= 0 )
        {
            if ( (counter++ % 20) == 0 )
                iguana_dPoWupdate(myinfo);
            endmilli = startmilli + 500;
        }
        else if ( myinfo->IAMLP != 0 )
            endmilli = startmilli + 1000;
        else endmilli = startmilli + 2000;
        while ( OS_milliseconds() < endmilli )
            usleep(10000);
        iter++;
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
    printf("Basilisk initialized\n");
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"

HASH_ARRAY_STRING(basilisk,balances,hash,vals,hexstr)
{
    char *retstr=0,*symbol; uint32_t basilisktag; struct basilisk_item *ptr,Lptr; int32_t timeoutmillis;
    if ( myinfo->NOTARY.RELAYID >= 0 )
        return(clonestr("{\"error\":\"special relays only do OUT and MSG\"}"));
    if ( vals == 0 )
        return(clonestr("{\"error\":\"need vals object\"}"));
    if ( (symbol= jstr(vals,"symbol")) != 0 || (symbol= jstr(vals,"coin")) != 0 )
        coin = iguana_coinfind(symbol);
    if ( jobj(vals,"history") == 0 )
        jaddnum(vals,"history",3);
    if ( jobj(vals,"fanout") == 0 )
        jaddnum(vals,"fanout",MAX(8,(int32_t)sqrt(myinfo->NOTARY.NUMRELAYS)+1));
    if ( jobj(vals,"numrequired") == 0 )
        jaddnum(vals,"numrequired",MIN(juint(vals,"fanout")/2,(int32_t)sqrt(myinfo->NOTARY.NUMRELAYS)));
    if ( jobj(vals,"addresses") == 0 )
    {
        jadd(vals,"addresses",iguana_getaddressesbyaccount(myinfo,coin,"*"));
        //printf("added all %s addresses: %s\n",coin->symbol,jprint(vals,0));
    } //else printf("have addresses.(%s)\n",jprint(jobj(vals,"addresses"),0));
    if ( (basilisktag= juint(vals,"basilisktag")) == 0 )
        basilisktag = rand();
    if ( (timeoutmillis= juint(vals,"timeout")) <= 0 )
        timeoutmillis = BASILISK_TIMEOUT;
    if ( coin != 0 )
    {
        if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
        {
            if ( (ptr= basilisk_bitcoinbalances(&Lptr,myinfo,coin,remoteaddr,basilisktag,timeoutmillis,vals)) != 0 )
            {
                retstr = ptr->retstr, ptr->retstr = 0;
                ptr->finished = OS_milliseconds() + 10000;
                return(retstr);
            }
            return(clonestr("{\"error\":\"no result\"}"));
        }
    } else printf("no coin\n");
    if ( (retstr= basilisk_standardservice("BAL",myinfo,0,hash,vals,hexstr,1)) != 0 )
    {
        basilisk_unspents_process(myinfo,coin,retstr);
    }
    return(retstr);
}

HASH_ARRAY_STRING(basilisk,history,hash,vals,hexstr)
{
    int64_t total = 0; int32_t i,n; char *symbol; cJSON *retjson,*unspents,*spends,*array; //struct basilisk_spend *s; struct basilisk_unspent *bu; int32_t i; struct iguana_waccount *wacct,*tmp; struct iguana_waddress *waddr,*tmp2; 
    if ( vals == 0 )
        return(clonestr("{\"error\":\"need vals object\"}"));
    //if ( coin == 0 )
    {
        if ( (symbol= jstr(vals,"symbol")) != 0 || (symbol= jstr(vals,"coin")) != 0 )
            coin = iguana_coinfind(symbol);
    }
    if ( coin == 0 )
        return(clonestr("{\"error\":\"couldnt find coin\"}"));
    unspents = cJSON_CreateArray();
    spends = cJSON_CreateArray();
    portable_mutex_lock(&myinfo->bu_mutex);
    //HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        //HASH_ITER(hh,wacct->waddr,waddr,tmp2)
        {
            if ( myinfo->Cunspents != 0 )
            {
                //printf("Cunspents.(%s)\n",jprint(waddr->Cunspents,0));
                if ( (array= jobj(myinfo->Cunspents,coin->symbol)) != 0 )
                {
                    if ( (n= cJSON_GetArraySize(array)) > 0 )
                    {
                        for (i=0; i<n; i++)
                            total += jdouble(jitem(array,i),"amount") * SATOSHIDEN;
                    }
                    jaddi(unspents,jduplicate(array));
                }
            }
            if ( myinfo->Cspends != 0 )
            {
                //printf("Cspends.(%s)\n",jprint(waddr->Cspends,0));
                if ( (array= jobj(myinfo->Cspends,coin->symbol)) != 0  )
                    jaddi(spends,jduplicate(array));
            }
        }
    }
    portable_mutex_unlock(&myinfo->bu_mutex);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jadd(retjson,"unspents",unspents);
    jadd(retjson,"spends",spends);
    jaddstr(retjson,"coin",coin->symbol);
    jaddnum(retjson,"balance",dstr(total));
    //printf("return history balance %s %.8f\n",coin->symbol,dstr(total));
    return(jprint(retjson,1));
}

#include "../includes/iguana_apiundefs.h"
