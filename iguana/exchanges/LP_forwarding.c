
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
//
//  LP_forwarding.c
//  marketmaker
//

struct LP_forwardinfo
{
    UT_hash_handle hh;
    bits256 pubkey;
    char pushaddr[64];
    int32_t pushsock;
    uint32_t lasttime;
} *LP_forwardinfos;
#define LP_KEEPALIVE (3600 * 24)

struct LP_forwardinfo *LP_forwardfind(bits256 pubkey)
{
    struct LP_forwardinfo *ptr=0;
    portable_mutex_lock(&LP_forwardmutex);
    HASH_FIND(hh,LP_forwardinfos,&pubkey,sizeof(pubkey),ptr);
    portable_mutex_unlock(&LP_forwardmutex);
    if ( ptr != 0 && ptr->lasttime > time(NULL)-LP_KEEPALIVE )
        return(ptr);
    else return(0);
}

char *LP_lookup(bits256 pubkey)
{
    if ( bits256_nonz(pubkey) == 0 )
        return(clonestr("{\"error\":\"illegal pubkey\"}"));
    if ( LP_forwardfind(pubkey) != 0 )
        return(clonestr("{\"result\":\"success\",\"forwarding\":1}"));
    else return(clonestr("{\"error\":\"notfound\"}"));
}

char *LP_register(bits256 pubkey,char *ipaddr)
{
    struct LP_forwardinfo *ptr=0; int32_t pushsock; char pushaddr[64];
    if ( ipaddr == 0 || ipaddr[0] == 0 || is_ipaddr(ipaddr) == 0 || bits256_nonz(pubkey) == 0 )
        return(clonestr("{\"error\":\"illegal ipaddr or null pubkey\"}"));
    //if ( strlen(pushaddr) <= strlen("tcp://") || is_ipaddr(pushaddr+strlen("tcp://")) == 0 )
    //    return(clonestr("{\"error\":\"illegal ipaddr\"}"));
    sprintf(pushaddr,"tcp://%s",ipaddr);
    char str[65]; printf("register.(%s) %s\n",pushaddr,bits256_str(str,pubkey));
    if ( (ptr= LP_forwardfind(pubkey)) != 0 )
    {
        ptr->lasttime = (uint32_t)time(NULL);
        return(clonestr("{\"error\":\"already registered\",\"registered\":1}"));
    }
    else if ( (pushsock= nn_socket(AF_SP,NN_PUSH)) < 0 )
        return(clonestr("{\"error\":\"out of sockets\"}"));
    else if ( nn_connect(pushsock,pushaddr) < 0 )
    {
        nn_close(pushsock);
        return(clonestr("{\"error\":\"cant connect\"}"));
    }
    else
    {
        char str[65]; printf("registered (%s) -> (%s)\n",bits256_str(str,pubkey),pushaddr);
        ptr = calloc(1,sizeof(*ptr));
        ptr->pubkey = pubkey;
        strcpy(ptr->pushaddr,pushaddr);
        ptr->pushsock = pushsock;
        ptr->lasttime = (uint32_t)time(NULL);
        portable_mutex_lock(&LP_forwardmutex);
        HASH_ADD_KEYPTR(hh,LP_forwardinfos,&ptr->pubkey,sizeof(ptr->pubkey),ptr);
        portable_mutex_unlock(&LP_forwardmutex);
        return(LP_lookup(pubkey));
    }
}

void LP_forwarding_register(bits256 pubkey,char *pushaddr,int32_t max)
{
    char *retstr; cJSON *retjson; struct LP_peerinfo *peer,*tmp; int32_t n=0,retval = -1;
    if ( pushaddr == 0 || pushaddr[0] == 0 || bits256_nonz(pubkey) == 0 )
    {
        printf("LP_forwarding_register illegal pushaddr or null pubkey\n");
        return;
    }
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        //printf("register with (%s)\n",peer->ipaddr);
        if ( (retstr= issue_LP_register(peer->ipaddr,peer->port,pubkey,pushaddr)) != 0 )
        {
            //printf("[%s] LP_register.(%s) returned.(%s)\n",pushaddr,peer->ipaddr,retstr);
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( jint(retjson,"registered") != 0 && ++n >= max )
                    retval = 0;
                free_json(retjson);
            }
            free(retstr);
        } else printf("error registering with %s\n",peer->ipaddr);
        if ( retval == 0 )
            break;
    }
}

cJSON *LP_dereference(cJSON *argjson,char *excludemethod)
{
    cJSON *reqjson = 0;
    if ( jstr(argjson,"method2") != 0 && strncmp(excludemethod,jstr(argjson,"method2"),strlen(excludemethod)) != 0 )
    {
        reqjson = jduplicate(argjson);
        jdelete(reqjson,"method");
        jaddstr(reqjson,"method",jstr(argjson,"method2"));
    }
    return(reqjson);
}

char *LP_forwardhex(int32_t pubsock,bits256 pubkey,char *hexstr)
{
    struct LP_forwardinfo *ptr=0; uint8_t *data; int32_t datalen=0,sentbytes=0; char *retstr=0; cJSON *retjson=0,*argjson=0,*reqjson=0;
    if ( hexstr == 0 || hexstr[0] == 0 )
        return(clonestr("{\"error\":\"nohex\"}"));
    datalen = (int32_t)strlen(hexstr) >> 1;
    data = malloc(datalen);
    decode_hex(data,datalen,hexstr);
    if ( (argjson= cJSON_Parse((char *)data)) != 0 )
        reqjson = LP_dereference(argjson,"forward");
    if ( bits256_nonz(pubkey) == 0 || bits256_cmp(pubkey,LP_mypubkey) == 0 )
    {
        if ( reqjson != 0 )
        {
            retstr = LP_command_process(LP_mypeer != 0 ? LP_mypeer->ipaddr : "127.0.0.1",LP_mypubsock,reqjson,0,0,LP_profitratio - 1.);
            printf("LP_forwardhex.(%s) -> (%s)\n",jprint(reqjson,0),retstr!=0?retstr:"");
            if ( pubsock >= 0 )
                LP_send(pubsock,jprint(reqjson,0),0);
        } else printf("LP_forwardhex couldnt parse (%s)\n",(char *)data);
    }
    else if ( (ptr= LP_forwardfind(pubkey)) != 0 )
    {
        if ( ptr->pushsock >= 0 )
        {
            printf("%s forwardhex.(%s)\n",ptr->pushaddr,(char *)data);
            sentbytes = LP_send(ptr->pushsock,(char *)data,0);
        }
        retjson = cJSON_CreateObject();
        if ( sentbytes == datalen )
        {
            jaddstr(retjson,"result","success");
            jaddnum(retjson,"forwarded",sentbytes);
            retstr = jprint(retjson,1);
        }
        else
        {
            jaddstr(retjson,"error","send error");
            jaddnum(retjson,"sentbytes",sentbytes);
            jaddnum(retjson,"datalen",datalen);
            retstr = jprint(retjson,1);
        }
    }
    else
    {
        char str[65]; printf("couldnt find %s to forward to\n",bits256_str(str,pubkey));
        if ( pubsock >= 0 )
            LP_send(pubsock,jprint(reqjson,0),0);
        retstr = clonestr("{\"error\":\"notfound\"}");
    }
    free(data);
    if ( reqjson != 0 )
        free_json(reqjson);
    if ( argjson != 0 )
        free_json(argjson);
    return(retstr);
}

int32_t LP_forward(bits256 pubkey,char *jsonstr,int32_t freeflag)
{
    struct LP_forwardinfo *ptr; struct LP_peerinfo *peer,*tmp; char *hexstr,*retstr; int32_t len,retval = -1; cJSON *retjson,*reqjson;
    if ( jsonstr == 0 || jsonstr[0] == 0 )
        return(-1);
    if ( bits256_nonz(pubkey) != 0 )
    {
        if ( IAMLP != 0 && (ptr= LP_forwardfind(pubkey)) != 0 && ptr->pushsock >= 0 && ptr->lasttime > time(NULL)-LP_KEEPALIVE )
        {
            return(LP_send(ptr->pushsock,jsonstr,1));
        }
    }
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        if ( bits256_nonz(pubkey) != 0 )
        {
            if ( (retstr= issue_LP_lookup(peer->ipaddr,peer->port,pubkey)) != 0 )
            {
                if ( (retjson= cJSON_Parse(retstr)) != 0 )
                {
                    if ( jint(retjson,"forwarding") != 0 && peer->pushsock >= 0 )
                        retval = 0;
                    free_json(retjson);
                }
                free(retstr);
            }
        } else retval = 0;
        if ( retval == 0 && peer->pushsock >= 0 )
        {
            //printf("found LPnode.(%s) forward.(%s)\n",peer->ipaddr,jsonstr);
            len = (int32_t)strlen(jsonstr) + 1;
            hexstr = malloc(len*2 + 1);
            init_hexbytes_noT(hexstr,(uint8_t *)jsonstr,len);
            if ( freeflag != 0 )
                free(jsonstr);
            reqjson = cJSON_CreateObject();
            jaddstr(reqjson,"method","forwardhex");
            jaddstr(reqjson,"hex",hexstr);
            jaddbits256(reqjson,"pubkey",pubkey);
            free(hexstr);
            return(LP_send(peer->pushsock,jprint(reqjson,1),1));
        } else retval = -1;
    }
    return(-1);
}


char *LP_broadcasted(cJSON *argjson)
{
    printf("RECV BROADCAST.(%s)\n",jprint(argjson,0));
    return(clonestr("{\"result\":\"need to update broadcast messages\"}"));
}


