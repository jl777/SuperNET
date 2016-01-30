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

#include "exchanges777.h"

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
        int32_t i; char str[65],str2[65];
        for (i=0; i<datalen; i++)
            printf("%02x",data[i]);
        printf(">>>>>>>>>>>>>>>> validated [%ld] len.%d (%s + %s)\n",(long)data-(long)msg,datalen,bits256_str(str,acct777_msgprivkey(data,datalen)),bits256_str(str2,msg->sig.pubkey));
        memset(buf,0,sizeof(buf));
        acct777_rwsig(1,buf,&msg->sig);
        memcpy(&msg->sig,buf,sizeof(buf));
        return(msg);
    } else printf("error validating instantdex msg\n");
    return(0);
}

char *instantdex_sendcmd(struct supernet_info *myinfo,cJSON *argjson,char *cmdstr,char *ipaddr,int32_t hops)
{
    char *reqstr,hexstr[8192]; uint8_t _msg[4096]; uint64_t nxt64bits; int32_t datalen;
    bits256 instantdexhash; struct instantdex_msghdr *msg;
    msg = (struct instantdex_msghdr *)_msg;
    memset(msg,0,sizeof(*msg));
    instantdexhash = calc_categoryhashes(0,"InstantDEX",0);
    category_subscribe(myinfo,instantdexhash,GENESIS_PUBKEY);
    if ( ipaddr == 0 || ipaddr[0] == 0 || strncmp(ipaddr,"127.0.0.1",strlen("127.0.0.1")) == 0 )
        return(clonestr("{\"error\":\"no ipaddr, need to send your ipaddr for now\"}"));
    jaddstr(argjson,"cmd",cmdstr);
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

void instantdex_updatesources(int32_t dir,struct exchange_quote *quotes,int32_t numquotes)
{
    int32_t i; struct exchange_quote *quote;
    for (i=0; i<numquotes; i++)
    {
        quote = &quotes[i << 1];
    }
}

char *instantdex_request(struct supernet_info *myinfo,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen)
{
    char *base,*rel,*request,*str; double volume; int32_t i,num,depth = 30;
    struct exchange_info *exchange; struct exchange_request *req,*active[64];
    if ( argjson != 0 )
    {
        num = 0;
        request = jstr(argjson,"request");
        base = jstr(argjson,"base");
        rel = jstr(argjson,"rel");
        volume = jdouble(argjson,"volume");
        if ( base != 0 && rel != 0 && volume > SMALLVAL )
        {
            for (i=0; i<myinfo->numexchanges; i++)
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
                    } else active[num++] = req;
                }
            }
            for (i=0; i<num; i++)
            {
                if ( volume < 0. && active[i]->numbids > 0 )
                    instantdex_updatesources(1,active[i]->bidasks,active[i]->numbids);
                else if ( volume > 0. && active[i]->numasks > 0 )
                    instantdex_updatesources(-1,&active[i]->bidasks[1],active[i]->numasks);
            }
            return(clonestr("{\"result\":\"reqprice response sent\"}"));
        }
        return(clonestr("{\"error\":\"request missing parameter\"}"));
    } else return(clonestr("{\"error\":\"request needs argjson\"}"));
}

char *instantdex_proposal(struct supernet_info *myinfo,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen)
{
    if ( argjson != 0 )
    {
        return(clonestr("{\"result\":\"proposal ignored\"}"));
        return(clonestr("{\"result\":\"proposal accepted\"}"));
    } else return(clonestr("{\"error\":\"response needs argjson\"}"));
}

char *instantdex_accepted(struct supernet_info *myinfo,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen)
{
    if ( argjson != 0 )
    {
        return(clonestr("{\"result\":\"proposal was accepted, confirmation sent\"}"));
    } else return(clonestr("{\"error\":\"response needs argjson\"}"));
}

char *instantdex_confirmed(struct supernet_info *myinfo,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen)
{
    if ( argjson != 0 )
    {
        return(clonestr("{\"result\":\"proposal was confirmed\"}"));
    } else return(clonestr("{\"error\":\"response needs argjson\"}"));
}

char *instantdex_parse(struct supernet_info *myinfo,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen)
{
    static struct { char *cmdstr; char *(*func)(struct supernet_info *myinfo,struct instantdex_msghdr *msg,cJSON *argjson,char *remoteaddr,uint64_t signerbits,uint8_t *data,int32_t datalen); uint64_t cmdbits; } cmds[] =
    {
        { "request", instantdex_request }, { "proposal", instantdex_proposal },
        { "accepted", instantdex_accepted }, { "confirmed", instantdex_confirmed },
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
            retstr = (*cmds[i].func)(myinfo,msg,argjson,remoteaddr,signerbits,data,datalen);
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
        printf("<<<<<<<<<<<<< sigsize.%ld VALIDATED [%ld] len.%d t%u allocsize.%d (%s) [%d]\n",sizeof(msg->sig),(long)data-(long)msg,datalen,msg->sig.timestamp,msg->sig.allocsize,(char *)msg->serialized,data[datalen-1]);
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

THREE_STRINGS_AND_DOUBLE(InstantDEX,request,reference,base,rel,volume)
{
    int32_t hops = 3; cJSON *argjson;
    if ( remoteaddr == 0 )
    {
        argjson = cJSON_CreateObject();
        jaddstr(argjson,"ref",reference);
        jaddstr(argjson,"base",base);
        jaddstr(argjson,"rel",rel);
        jaddnum(argjson,"volume",volume);
        return(instantdex_sendcmd(myinfo,argjson,"request",myinfo->ipaddr,hops));
    } else return(clonestr("{\"error\":\"InstantDEX API request only local usage!\"}"));
}

cJSON *InstantDEX_argjson(char *reference,char *message,bits256 basetxid,bits256 reltxid,int32_t iter,int32_t val,int32_t val2)
{
    cJSON *argjson = cJSON_CreateObject();
    jaddstr(argjson,"ref",reference);
    if ( message != 0 && message[0] != 0 )
        jaddstr(argjson,"message",message);
    jaddbits256(argjson,"basetxid",basetxid);
    jaddbits256(argjson,"reltxid",reltxid);
    if ( iter != 3 )
    {
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

TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,proposal,reference,message,basetxid,reltxid,duration,flags)
{
    int32_t hops = 3; cJSON *argjson; char *retstr;
    if ( remoteaddr == 0 )
    {
        argjson = InstantDEX_argjson(reference,message,basetxid,reltxid,1,duration,flags);
        retstr = instantdex_sendcmd(myinfo,argjson,"proposal",myinfo->ipaddr,hops);
        free_json(argjson);
        return(retstr);
    } else return(clonestr("{\"error\":\"InstantDEX API proposal only local usage!\"}"));
}

TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,accept,reference,message,basetxid,reltxid,duration,flags)
{
    int32_t hops = 3; cJSON *argjson; char *retstr;
    if ( remoteaddr == 0 )
    {
        argjson = InstantDEX_argjson(reference,message,basetxid,reltxid,2,duration,flags);
        retstr = instantdex_sendcmd(myinfo,argjson,"accept",myinfo->ipaddr,hops);
        free_json(argjson);
        return(retstr);
    } else return(clonestr("{\"error\":\"InstantDEX API accept only local usage!\"}"));
}

TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,confirm,reference,message,basetxid,reltxid,baseheight,relheight)
{
    int32_t hops = 3; cJSON *argjson; char *retstr;
    if ( remoteaddr == 0 )
    {
        argjson = InstantDEX_argjson(reference,message,basetxid,reltxid,3,baseheight,relheight);
        retstr = instantdex_sendcmd(myinfo,argjson,"confirm",myinfo->ipaddr,hops);
        free_json(argjson);
        return(retstr);
    } else return(clonestr("{\"error\":\"InstantDEX API confirm only local usage!\"}"));
}

#include "../includes/iguana_apiundefs.h"

