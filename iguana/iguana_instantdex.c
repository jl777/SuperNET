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

// selftest supports against allpairs list

#include "exchanges777.h"

#define INSTANTDEX_HOPS 3
#define INSTANTDEX_DURATION 60

#define INSTANTDEX_NXTOFFER 1
#define INSTANTDEX_REQUEST 2
#define INSTANTDEX_PROPOSE 3
#define INSTANTDEX_ACCEPT 4
#define INSTANTDEX_CONFIRM 5

struct instantdex_entry { char base[24],rel[24]; double price,volume,pendingvolume; uint32_t expiration,nonce; };
struct instantdex_accept { struct queueitem DL; uint64_t txid; struct instantdex_entry A; };

cJSON *InstantDEX_argjson(char *reference,char *message,char *othercoinaddr,char *otherNXTaddr,int32_t iter,int32_t val,int32_t val2)
{
    cJSON *argjson = cJSON_CreateObject();
    if ( reference != 0 )
        jaddstr(argjson,"refstr",reference);
    if ( message != 0 && message[0] != 0 )
        jaddstr(argjson,"message",message);
    if ( othercoinaddr != 0 && othercoinaddr[0] != 0 )
        jaddstr(argjson,"othercoinaddr",othercoinaddr);
    if ( otherNXTaddr != 0 && otherNXTaddr[0] != 0 )
        jaddstr(argjson,"otherNXTaddr",otherNXTaddr);
    //jaddbits256(argjson,"basetxid",basetxid);
    //jaddbits256(argjson,"reltxid",reltxid);
    if ( iter != 3 )
    {
        if ( val == 0 )
            val = INSTANTDEX_DURATION;
        jaddnum(argjson,"duration",val);
        jaddnum(argjson,"flags",val2);
    }
    else
    {
        if ( val > 0 )
            jaddnum(argjson,"baseheight",val);
        if ( val2 > 0 )
            jaddnum(argjson,"relheight",val2);
    }
    return(argjson);
}

int32_t instantdex_rwdata(int32_t rwflag,uint64_t cmdbits,uint8_t *data,int32_t datalen)
{
    // need to inplace serialize/deserialize here
    return(datalen);
}

struct instantdex_msghdr *instantdex_msgcreate(struct supernet_info *myinfo,struct instantdex_msghdr *msg,int32_t datalen)
{
    bits256 otherpubkey; uint64_t signerbits; uint32_t timestamp; uint8_t buf[sizeof(msg->sig)],*data;
    memset(&msg->sig,0,sizeof(msg->sig));
    datalen += (int32_t)(sizeof(*msg) - sizeof(msg->sig));
    data = (void *)((long)msg + sizeof(msg->sig));
    otherpubkey = acct777_msgpubkey(data,datalen);
    timestamp = (uint32_t)time(NULL);
    acct777_sign(&msg->sig,myinfo->privkey,otherpubkey,timestamp,data,datalen);
    if ( (signerbits= acct777_validate(&msg->sig,acct777_msgprivkey(data,datalen),msg->sig.pubkey)) != 0 )
    {
        //int32_t i;
        //char str[65],str2[65];
        //for (i=0; i<datalen; i++)
        //    printf("%02x",data[i]);
        //printf(">>>>>>>>>>>>>>>> validated [%ld] len.%d (%s + %s)\n",(long)data-(long)msg,datalen,bits256_str(str,acct777_msgprivkey(data,datalen)),bits256_str(str2,msg->sig.pubkey));
        memset(buf,0,sizeof(buf));
        acct777_rwsig(1,buf,&msg->sig);
        memcpy(&msg->sig,buf,sizeof(buf));
        return(msg);
    } else printf("error validating instantdex msg\n");
    return(0);
}

char *instantdex_sendcmd(struct supernet_info *myinfo,cJSON *argjson,char *cmdstr,char *ipaddr,int32_t hops)
{
    char *reqstr,hexstr[8192]; uint8_t _msg[4096]; uint64_t nxt64bits; int32_t i,datalen;
    bits256 instantdexhash; struct instantdex_msghdr *msg;
    msg = (struct instantdex_msghdr *)_msg;
    memset(msg,0,sizeof(*msg));
    instantdexhash = calc_categoryhashes(0,"InstantDEX",0);
    category_subscribe(myinfo,instantdexhash,GENESIS_PUBKEY);
    if ( ipaddr == 0 || ipaddr[0] == 0 || strncmp(ipaddr,"127.0.0.1",strlen("127.0.0.1")) == 0 )
        return(clonestr("{\"error\":\"no ipaddr, need to send your ipaddr for now\"}"));
    jaddstr(argjson,"cmd",cmdstr);
    for (i=0; i<sizeof(msg->cmd); i++)
        if ( (msg->cmd[i]= cmdstr[i]) == 0 )
            break;
    jaddstr(argjson,"agent","SuperNET");
    jaddstr(argjson,"method","DHT");
    jaddstr(argjson,"traderip",ipaddr);
    jaddbits256(argjson,"categoryhash",instantdexhash);
    jaddbits256(argjson,"traderpub",myinfo->myaddr.persistent);
    nxt64bits = acct777_nxt64bits(myinfo->myaddr.persistent);
    reqstr = jprint(argjson,1);
    datalen = (int32_t)(strlen(reqstr) + 1);
    memcpy(msg->serialized,reqstr,datalen);
    free(reqstr);
    if ( (datalen+sizeof(*msg))*2+1 < sizeof(hexstr) && instantdex_msgcreate(myinfo,msg,datalen) != 0 )
    {
        printf("instantdex send.(%s)\n",cmdstr);
        init_hexbytes_noT(hexstr,(uint8_t *)msg,msg->sig.allocsize);
        return(SuperNET_categorymulticast(myinfo,0,instantdexhash,GENESIS_PUBKEY,hexstr,0,hops,1));
    }
    else
    {
        printf("cant msgcreate\n");
        return(clonestr("{\"error\":\"couldnt create instantdex message\"}"));
    }
}

int32_t instantdex_updatesources(struct exchange_info *exchange,struct exchange_quote *sortbuf,int32_t n,int32_t max,int32_t ind,int32_t dir,struct exchange_quote *quotes,int32_t numquotes)
{
    int32_t i; struct exchange_quote *quote;
    //printf("instantdex_updatesources update dir.%d numquotes.%d\n",dir,numquotes);
    for (i=0; i<numquotes; i++)
    {
        quote = &quotes[i << 1];
        //printf("n.%d ind.%d i.%d dir.%d price %.8f vol %.8f\n",n,ind,i,dir,quote->price,quote->volume);
        if ( quote->price > SMALLVAL )
        {
            sortbuf[n] = *quote;
            sortbuf[n].val = ind;
            sortbuf[n].exchangebits = exchange->exchangebits;
            //printf("sortbuf[%d] <-\n",n*2);
            if ( ++n >= max )
                break;
        }
    }
    return(n);
}

double instantdex_aveprice(struct supernet_info *myinfo,struct exchange_quote *sortbuf,int32_t max,double *totalvolp,char *base,char *rel,double relvolume,cJSON *argjson)
{
    char *str; double totalvol,pricesum; uint32_t timestamp;
    struct exchange_quote quote; int32_t i,n,dir,num,depth = 100;
    struct exchange_info *exchange; struct exchange_request *req,*active[64];
    timestamp = (uint32_t)time(NULL);
    if ( relvolume < 0. )
        relvolume = -relvolume, dir = -1;
    else dir = 1;
    memset(sortbuf,0,sizeof(*sortbuf) * max);
    if ( base != 0 && rel != 0 && relvolume > SMALLVAL )
    {
        for (i=num=0; i<myinfo->numexchanges && num < sizeof(active)/sizeof(*active); i++)
        {
            if ( (exchange= myinfo->tradingexchanges[i]) != 0 )
            {
                if ( (req= exchanges777_baserelfind(exchange,base,rel,'M')) == 0 )
                {
                    if ( (str= exchanges777_Qprices(exchange,base,rel,30,1,depth,argjson,1,exchange->commission)) != 0 )
                        free(str);
                    req = exchanges777_baserelfind(exchange,base,rel,'M');
                }
                if ( req == 0 )
                {
                    if ( (*exchange->issue.supports)(exchange,base,rel,argjson) != 0 )
                        printf("unexpected null req.(%s %s) %s\n",base,rel,exchange->name);
                }
                else
                {
                    //printf("active.%s\n",exchange->name);
                    active[num++] = req;
                }
            }
        }
        for (i=n=0; i<num; i++)
        {
            if ( dir < 0 && active[i]->numbids > 0 )
                n = instantdex_updatesources(active[i]->exchange,sortbuf,n,max,i,1,active[i]->bidasks,active[i]->numbids);
            else if ( dir > 0 && active[i]->numasks > 0 )
                n = instantdex_updatesources(active[i]->exchange,sortbuf,n,max,i,-1,&active[i]->bidasks[1],active[i]->numasks);
        }
        //printf("dir.%d %s/%s numX.%d n.%d\n",dir,base,rel,num,n);
        if ( dir < 0 )
            revsort64s(&sortbuf[0].satoshis,n,sizeof(*sortbuf));
        else sort64s(&sortbuf[0].satoshis,n,sizeof(*sortbuf));
        for (totalvol=pricesum=i=0; i<n && totalvol < relvolume; i++)
        {
            quote = sortbuf[i];
            //printf("n.%d i.%d price %.8f %.8f %.8f\n",n,i,dstr(sortbuf[i].satoshis),sortbuf[i].price,quote.volume);
            if ( quote.satoshis != 0 )
            {
                pricesum += (quote.price * quote.volume);
                totalvol += quote.volume;
                //printf("i.%d of %d %12.8f vol %.8f %s | aveprice %.8f total vol %.8f\n",i,n,sortbuf[i].price,quote.volume,active[quote.val]->exchange->name,pricesum/totalvol,totalvol);
            }
        }
        if ( totalvol > 0. )
        {
            *totalvolp = totalvol;
            return(pricesum / totalvol);
        }
    }
    *totalvolp = 0;
    return(0);
}

cJSON *instantdex_acceptjson(struct instantdex_accept *ap)
{
    cJSON *item = cJSON_CreateObject();
    jadd64bits(item,"orderid",ap->txid);
    jaddstr(item,"base",ap->A.base);
    jaddstr(item,"rel",ap->A.rel);
    jaddnum(item,"price",ap->A.price);
    jaddnum(item,"volume",ap->A.volume);
    jaddnum(item,"pendingvolume",ap->A.pendingvolume);
    jaddnum(item,"expiresin",ap->A.expiration - time(NULL));
    return(item);
}

double instantdex_acceptable(struct supernet_info *myinfo,cJSON *array,char *refstr,char *base,char *rel,double volume)
{
    struct instantdex_accept PAD,*ap,*retap = 0; double price = 0.; uint32_t now;
    now = (uint32_t)time(NULL);
    memset(&PAD,0,sizeof(PAD));
    queue_enqueue("acceptableQ",&myinfo->acceptableQ,&PAD.DL,0);
    while ( (ap= queue_dequeue(&myinfo->acceptableQ,0)) != 0 && ap != &PAD )
    {
        if ( volume > 0. && (strcmp(base,"*") == 0 || strcmp(base,ap->A.base) == 0) && (strcmp(rel,"*") == 0 || strcmp(rel,ap->A.rel) == 0) && volume < (ap->A.volume - ap->A.pendingvolume) )
        {
            if ( ap->A.price > price )
            {
                price = ap->A.price;
                retap = ap;
            }
        }
        if ( now < ap->A.expiration )
        {
            if ( array != 0 )
                jaddi(array,instantdex_acceptjson(ap));
            queue_enqueue("acceptableQ",&myinfo->acceptableQ,&ap->DL,0);
        }
    }
    if ( retap != 0 )
    {
        retap->A.pendingvolume -= volume;
        price = retap->A.price;
    }
    return(price);
}

char *instantdex_request(struct supernet_info *myinfo,char *cmdstr,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen) // receiving side
{
    struct NXT_tx feeT; char fullhash[256],*othercoinaddr; cJSON *feejson; uint64_t assetbits = 0;
    char *base,*rel,*request,*refstr,*nextcmdstr,*message,*traderip,*otherNXTaddr;
    double volume,price; cJSON *newjson; int32_t duration,flags,nextcmd;
    int32_t num,depth; //struct exchange_quote sortbuf[1000]; bits256 basetxid,reltxid;,aveprice,totalvol
    if ( argjson != 0 )
    {
        num = 0;
        depth = 30;
        request = jstr(argjson,"request");
        base = jstr(argjson,"base");
        rel = jstr(argjson,"rel");
        refstr = jstr(argjson,"refstr");
        volume = jdouble(argjson,"volume");
        duration = juint(argjson,"duration");
        flags = juint(argjson,"flags");
        nextcmd = 0;
        nextcmdstr = message = "";
        if ( (traderip= jstr(argjson,"traderip")) != 0 && strcmp(traderip,myinfo->ipaddr) == 0 )
        {
            printf("got my own request\n");
            return(clonestr("{\"result\":\"got my own request\"}"));
        }
        // NXToffer:
        // sends NXT assetid, volume and desired rel, also reftx
        if ( strcmp(cmdstr,"NXToffer") == 0 )
        {
            if ( (price= instantdex_acceptable(myinfo,0,refstr,base,rel,volume)) > 0. )
            {
                // sends NXT assetid, volume and desired
                if ( strcmp(base,"NXT") == 0 || strcmp(base,"nxt") == 0 )
                    assetbits = NXT_ASSETID;
                else if ( is_decimalstr(base) > 0 )
                    assetbits = calc_nxt64bits(base);
                if ( assetbits != 0 )
                {
                    nextcmd = INSTANTDEX_REQUEST;
                    nextcmdstr = "request";
                }
            }
        }
        else if ( strcmp(cmdstr,"request") == 0 )
        {
            // request:
            // other node sends (othercoin, othercoinaddr, otherNXT and reftx that expires before phasedtx)
            if ( (strcmp(rel,"BTC") == 0 || strcmp(base,"BTC") == 0) && (price= instantdex_acceptable(myinfo,0,refstr,base,rel,volume)) > 0. )
            {
                //aveprice = instantdex_aveprice(myinfo,sortbuf,(int32_t)(sizeof(sortbuf)/sizeof(*sortbuf)),&totalvol,base,rel,volume,argjson);
                set_NXTtx(myinfo,&feeT,assetbits,SATOSHIDEN*3,calc_nxt64bits(INSTANTDEX_ACCT),-1);
                if ( (feejson= gen_NXT_tx_json(myinfo,fullhash,&feeT,0,1.)) != 0 )
                    free_json(feejson);
                nextcmd = INSTANTDEX_PROPOSE;
                nextcmdstr = "proposal";
                othercoinaddr = myinfo->myaddr.BTC;
                otherNXTaddr = myinfo->myaddr.NXTADDR;
            }
        }
        else
        {
            if ( strcmp(cmdstr,"proposal") == 0 )
            {
                // proposal:
                // NXT node submits phasedtx that refers to it, but it wont confirm
                nextcmd = INSTANTDEX_ACCEPT;
                nextcmdstr = "accept";
                message = "";
                //instantdex_phasetxsubmit(refstr);
            }
            else if ( strcmp(cmdstr,"accept") == 0 )
            {
                // accept:
                // other node verifies unconfirmed has phasedtx and broadcasts cltv, also to NXT node, releases trigger
                nextcmd = INSTANTDEX_CONFIRM;
                nextcmdstr = "confirm";
                message = "";
                //instantdex_phasedtxverify();
                //instantdex_cltvbroadcast();
                //instantdex_releasetrigger();
            }
            else if ( strcmp(cmdstr,"confirm") == 0 )
            {
                // confirm:
                // NXT node verifies bitcoin txbytes has proper payment and cashes in with onetimepubkey
                // BTC* node approves phased tx with onetimepubkey
                //instantdex_cltvverify();
                //instantdex_phasetxapprove();
                return(clonestr("{\"error\":\"trade confirmed\"}"));
            }
        }
        if ( nextcmd != 0 && (newjson= InstantDEX_argjson(refstr,message,othercoinaddr,otherNXTaddr,nextcmd,duration,flags)) != 0 )
        {
            jaddnum(newjson,"price",price);
            jaddnum(newjson,"volume",volume);
            return(instantdex_sendcmd(myinfo,newjson,nextcmdstr,myinfo->ipaddr,INSTANTDEX_HOPS));
        }
    }
    return(clonestr("{\"error\":\"request needs argjson\"}"));
}

char *instantdex_parse(struct supernet_info *myinfo,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen)
{
    static struct { char *cmdstr; char *(*func)(struct supernet_info *myinfo,char *cmdstr,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen); uint64_t cmdbits; } cmds[] =
    {
        { "NXToffer", instantdex_request }, { "request", instantdex_request },
        { "proposal", instantdex_request },
        { "accept", instantdex_request },
        { "confirm", instantdex_request },
    };
    char *retstr = 0; int32_t i; uint64_t cmdbits;
    if ( cmds[0].cmdbits == 0 )
    {
        for (i=0; i<sizeof(cmds)/sizeof(*cmds); i++)
            cmds[i].cmdbits = stringbits(cmds[i].cmdstr);
    }
    cmdbits = stringbits(msg->cmd);
    for (i=0; i<sizeof(cmds)/sizeof(*cmds); i++)
    {
        if ( cmds[i].cmdbits == cmdbits )
        {
            printf("parsed.(%s)\n",cmds[i].cmdstr);
            retstr = (*cmds[i].func)(myinfo,cmds[i].cmdstr,msg,argjson,remoteaddr,signerbits,data,datalen);
            break;
        }
    }
    return(retstr);
}

char *InstantDEX_hexmsg(struct supernet_info *myinfo,void *ptr,int32_t len,char *remoteaddr)
{
    struct instantdex_msghdr *msg = ptr; cJSON *argjson; int32_t n,datalen,newlen,flag = 0;
    uint64_t signerbits; uint8_t *data; uint8_t tmp[sizeof(msg->sig)]; char *retstr = 0;
    acct777_rwsig(0,(void *)&msg->sig,(void *)tmp);
    memcpy(&msg->sig,tmp,sizeof(msg->sig));
    datalen = len  - (int32_t)sizeof(msg->sig);
    data = (void *)((long)msg + sizeof(msg->sig));
    if ( remoteaddr != 0 && remoteaddr[0] == 0 && strcmp("127.0.0.1",remoteaddr) == 0 && ((uint8_t *)msg)[len-1] == 0 && (argjson= cJSON_Parse((char *)msg)) != 0 )
    {
        printf("instantdex_hexmsg RESULT.(%s)\n",jprint(argjson,0));
        retstr = instantdex_parse(myinfo,msg,argjson,0,myinfo->myaddr.nxt64bits,0,0);
        free_json(argjson);
        return(retstr);
    }
    //printf("msg.%p len.%d data.%p datalen.%d crc.%u %s\n",msg,len,data,datalen,calc_crc32(0,(void *)msg,len),bits256_str(str,msg->sig.pubkey));
    //return(0);
    else if ( (signerbits= acct777_validate(&msg->sig,acct777_msgprivkey(data,datalen),msg->sig.pubkey)) != 0 )
    {
        flag++;
        printf("InstantDEX_hexmsg <<<<<<<<<<<<< sigsize.%ld VALIDATED [%ld] len.%d t%u allocsize.%d (%s) [%d]\n",sizeof(msg->sig),(long)data-(long)msg,datalen,msg->sig.timestamp,msg->sig.allocsize,(char *)msg->serialized,data[datalen-1]);
        if ( data[datalen-1] == 0 && (argjson= cJSON_Parse((char *)msg->serialized)) != 0 )
            retstr = instantdex_parse(myinfo,msg,argjson,remoteaddr,signerbits,data,datalen);
        else
        {
            newlen = (int32_t)(msg->sig.allocsize - sizeof(*msg));
            data = msg->serialized;
            if ( msg->serialized[len - 1] == 0 )
            {
                if ( (argjson= cJSON_Parse((char *)msg->serialized)) != 0 )
                {
                    n = (int32_t)(strlen((char *)msg->serialized) + 1);
                    newlen -= n;
                    if ( n >= 0 )
                        data = &msg->serialized[n];
                    else data = 0;
                }
            }
            if ( data != 0 )
                retstr = instantdex_parse(myinfo,msg,argjson,remoteaddr,signerbits,data,newlen);
        }
    }
    if ( argjson != 0 )
        free_json(argjson);
    return(retstr);
}

#include "../includes/iguana_apidefs.h"

// NXTrequest:
// sends NXT assetid, volume and desired
// request:
// other node sends (othercoin, othercoinaddr, otherNXT and reftx that expires well before phasedtx)
// proposal:
// NXT node submits phasedtx that refers to it, but it wont confirm
// approve:
// other node verifies unconfirmed has phasedtx and broadcasts cltv, also to NXT node, releases trigger
// confirm:
// NXT node verifies bitcoin txbytes has proper payment and cashes in with onetimepubkey
// BTC* node approves phased tx with onetimepubkey

TWO_STRINGS_AND_TWO_DOUBLES(InstantDEX,acceptable,base,rel,price,volume)
{
    struct instantdex_accept A; bits256 hash;
    memset(&A,0,sizeof(A));
    OS_randombytes((uint8_t *)&A.A.nonce,sizeof(A.A.nonce));
    safecopy(A.A.base,base,sizeof(A.A.base));
    safecopy(A.A.rel,rel,sizeof(A.A.rel));
    A.A.price = price, A.A.volume = volume;
    A.A.expiration = (uint32_t)time(NULL) + 3600;
    vcalc_sha256(0,hash.bytes,(void *)&A.A,sizeof(A.A));
    A.txid = hash.txid;
    queue_enqueue("acceptableQ",&myinfo->acceptableQ,&A.DL,0);
    return(clonestr("{\"result\":\"added acceptable\"}"));
}

THREE_STRINGS_AND_DOUBLE(InstantDEX,NXToffer,reference,base,rel,volume) // initiator
{
    int32_t hops = INSTANTDEX_HOPS; cJSON *argjson;
    if ( remoteaddr == 0 )
    {
        argjson = cJSON_CreateObject();
        jaddstr(argjson,"refstr",reference);
        jaddstr(argjson,"base",base);
        jaddstr(argjson,"rel",rel);
        jaddnum(argjson,"volume",volume);
        return(instantdex_sendcmd(myinfo,argjson,"NXToffer",myinfo->ipaddr,hops));
    } else return(clonestr("{\"error\":\"InstantDEX API request only local usage!\"}"));
}

THREE_STRINGS_AND_DOUBLE(InstantDEX,request,reference,base,rel,volume) // initiator
{
    int32_t hops = INSTANTDEX_HOPS; cJSON *argjson;
    if ( remoteaddr == 0 )
    {
        argjson = cJSON_CreateObject();
        jaddstr(argjson,"refstr",reference);
        jaddstr(argjson,"base",base);
        jaddstr(argjson,"rel",rel);
        jaddnum(argjson,"volume",volume);
        return(instantdex_sendcmd(myinfo,argjson,"request",myinfo->ipaddr,hops));
    } else return(clonestr("{\"error\":\"InstantDEX API request only local usage!\"}"));
}

TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,proposal,reference,message,basetxid,reltxid,duration,flags) // responder
{
    int32_t hops = INSTANTDEX_HOPS; cJSON *argjson; char str[65],str2[65];
    if ( remoteaddr == 0 )
    {
        argjson = InstantDEX_argjson(reference,message,bits256_str(str,basetxid),bits256_str(str2,basetxid),INSTANTDEX_PROPOSE,duration,flags);
        return(instantdex_sendcmd(myinfo,argjson,"proposal",myinfo->ipaddr,hops));
    } else return(clonestr("{\"error\":\"InstantDEX API proposal only local usage!\"}"));
}

/*TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,accept,reference,message,basetxid,reltxid,duration,flags)
{
    int32_t hops = INSTANTDEX_HOPS; cJSON *argjson;
    if ( remoteaddr == 0 )
    {
        argjson = InstantDEX_argjson(reference,message,basetxid,reltxid,INSTANTDEX_ACCEPT,duration,flags);
        return(instantdex_sendcmd(myinfo,argjson,"accept",myinfo->ipaddr,hops));
    } else return(clonestr("{\"error\":\"InstantDEX API accept only local usage!\"}"));
}

TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,confirm,reference,message,basetxid,reltxid,baseheight,relheight)
{
    int32_t hops = INSTANTDEX_HOPS; cJSON *argjson;
    if ( remoteaddr == 0 )
    {
        argjson = InstantDEX_argjson(reference,message,basetxid,reltxid,INSTANTDEX_CONFIRM,baseheight,relheight);
        return(instantdex_sendcmd(myinfo,argjson,"confirm",myinfo->ipaddr,hops));
    } else return(clonestr("{\"error\":\"InstantDEX API confirm only local usage!\"}"));
}*/

#include "../includes/iguana_apiundefs.h"

