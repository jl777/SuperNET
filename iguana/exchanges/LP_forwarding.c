
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

char *LP_register(bits256 pubkey,char *pushaddr)
{
    struct LP_forwardinfo *ptr=0; int32_t pushsock;
    if ( pushaddr == 0 || pushaddr[0] == 0 || bits256_nonz(pubkey) == 0 )
        return(clonestr("{\"error\":\"illegal ipaddr\"}"));
    if ( strlen(pushaddr) <= strlen("tcp://") || is_ipaddr(pushaddr+strlen("tcp://")) == 0 )
        return(clonestr("{\"error\":\"illegal ipaddr\"}"));
    if ( (ptr= LP_forwardfind(pubkey)) != 0 )
    {
        ptr->lasttime = (uint32_t)time(NULL);
        return(clonestr("{\"error\":\"already registered\"}"));
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

char *LP_forward(bits256 pubkey,char *hexstr) 
{
    struct LP_forwardinfo *ptr=0; uint8_t *data; int32_t datalen=0,sentbytes=0; cJSON *retjson;
    if ( hexstr == 0 || hexstr[0] == 0 )
        return(clonestr("{\"error\":\"nohex\"}"));
    if ( (ptr= LP_forwardfind(pubkey)) != 0 )
    {
        if ( ptr->pushsock >= 0 )
        {
            datalen = (int32_t)strlen(hexstr) >> 1;
            data = malloc(datalen);
            decode_hex(data,datalen,hexstr);
            sentbytes = LP_send(ptr->pushsock,(char *)data,1);
        }
        retjson = cJSON_CreateObject();
        if ( sentbytes == datalen )
        {
            jaddstr(retjson,"result","success");
            jaddnum(retjson,"forwarded",sentbytes);
            return(jprint(retjson,1));
        }
        else
        {
            jaddstr(retjson,"error","send error");
            jaddnum(retjson,"sentbytes",sentbytes);
            jaddnum(retjson,"datalen",datalen);
            return(jprint(retjson,1));
        }
    } else return(clonestr("{\"error\":\"notfound\"}"));
}

void LP_forwarding_register(bits256 pubkey,char *pushaddr,int32_t broadcastflag)
{
    char *retstr; cJSON *retjson; struct LP_peerinfo *peer,*tmp; int32_t n=0,retval = -1;
    if ( pushaddr == 0 || pushaddr[0] == 0 || bits256_nonz(pubkey) == 0 )
        return;
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        if ( broadcastflag == 0 && (rand() % 100) < 66 )
            continue;
        if ( (retstr= issue_LP_register(peer->ipaddr,peer->port,pubkey,pushaddr)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( jint(retjson,"registered") != 0 )
                    retval = 0;
                free_json(retjson);
            }
            free(retstr);
        }
        if ( broadcastflag == 0 && retval == 0 )
            break;
        n++;
    }
}

int32_t LP_pubkey_send(bits256 pubkey,char *jsonstr,int32_t freeflag)
{
    struct LP_forwardinfo *ptr; struct LP_peerinfo *peer,*tmp; char *hexstr,*retstr; int32_t len,retval = -1; cJSON *retjson;
    if ( jsonstr == 0 || jsonstr[0] == 0 || bits256_nonz(pubkey) == 0 )
        return(-1);
    if ( IAMLP != 0 && (ptr= LP_forwardfind(pubkey)) != 0 && ptr->pushsock >= 0 && ptr->lasttime > time(NULL)-LP_KEEPALIVE )
    {
        return(LP_send(ptr->pushsock,jsonstr,1));
    }
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
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
        if ( retval == 0 )
        {
            printf("found LPnode.(%s) forward.(%s)\n",peer->ipaddr,jsonstr);
            len = (int32_t)strlen(jsonstr) + 1;
            hexstr = malloc(len*2 + 1);
            init_hexbytes_noT(hexstr,(uint8_t *)jsonstr,len);
            if ( freeflag != 0 )
                free(jsonstr);
            if ( peer->pushsock >= 0 )
                return(LP_send(peer->pushsock,hexstr,1));
        }
    }
    return(-1);
}



