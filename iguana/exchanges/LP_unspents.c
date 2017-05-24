//
//  LP_unspents.c
//  marketmaker
//
//  Created by Mac on 5/23/17.
//  Copyright © 2017 SuperNET. All rights reserved.
//

#include <stdio.h>

char *default_LPnodes[] = { "5.9.253.195", "5.9.253.196", "5.9.253.197", "5.9.253.198", "5.9.253.199", "5.9.253.200", "5.9.253.201", "5.9.253.202", "5.9.253.203", "5.9.253.204" };
portable_mutex_t LP_mutex;
int32_t LP_numpeers;

struct LP_peerinfo
{
    UT_hash_handle hh;
    uint64_t ip_port;
    double profitmargin;
    uint32_t ipbits,errortime,errors,numpeers,foundtime;
    char ipaddr[64];
    uint16_t port;
} *LP_peerinfos;

void LP_addutxo(char *coin,bits256 txid,int32_t vout,uint64_t satoshis,bits256 deposittxid,int32_t depositvout,uint64_t depositsatoshis,char *spendscript,char *coinaddr,char *ipaddr,uint16_t port)
{
    printf("%s:%u LP_addutxo.(%.8f %.8f)\n",ipaddr,port,dstr(satoshis),dstr(depositsatoshis));
}

int32_t LP_maxvalue(uint64_t *values,int32_t n)
{
    int32_t i,maxi = -1; uint64_t maxval = 0;
    for (i=0; i<n; i++)
        if ( values[i] > maxval )
        {
            maxi = i;
            maxval = values[i];
        }
    return(maxi);
}

int32_t LP_nearestvalue(uint64_t *values,int32_t n,uint64_t targetval)
{
    int32_t i,mini = -1; int64_t dist; uint64_t mindist = (1 << 31);
    for (i=0; i<n; i++)
    {
        dist = (values[i] - targetval);
        if ( dist < 0 && -dist < values[i]/10 )
            dist = -dist;
        if ( dist >= 0 && dist < mindist )
        {
            mini = i;
            mindist = dist;
        }
    }
    return(mini);
}

uint64_t LP_privkey_init(char *coin,uint8_t addrtype,char *passphrase,char *wifstr)
{
    char *retstr,coinaddr[64],*script; cJSON *array,*item; bits256 txid,deposittxid; int32_t used,i,n,vout,depositvout; uint64_t *values,satoshis,depositval,targetval,value,total = 0; bits256 privkey,pubkey; uint8_t pubkey33[33];
    if ( passphrase != 0 )
        conv_NXTpassword(privkey.bytes,pubkey.bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
    else privkey = iguana_wif2privkey(wifstr);
    iguana_priv2pub(pubkey33,coinaddr,privkey,addrtype);
    retstr = iguana_listunspent(coin,coinaddr);
    if ( retstr != 0 && retstr[0] == '[' && retstr[1] == ']' )
        free(retstr), retstr = 0;
    if ( retstr == 0 )
    {
        if ( (retstr= DEX_listunspent(coin,coinaddr)) == 0 )
        {
            printf("null listunspent\n");
            return(0);
        }
    }
    printf("LP_privkey_init.(%s)\n",retstr);
    if ( (array= cJSON_Parse(retstr)) != 0 )
    {
        if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            values = calloc(n,sizeof(*values));
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                satoshis = SATOSHIDEN * jdouble(item,"amount");
                values[i] = satoshis;
                printf("%.8f ",dstr(satoshis));
            }
            printf("array.%d\n",n);
            used = 0;
            while ( used < n )
            {
                if ( (i= LP_maxvalue(values,n)) >= 0 )
                {
                    item = jitem(array,i);
                    deposittxid = jbits256(item,"txid");
                    depositvout = juint(item,"vout");
                    script = jstr(item,"scriptPubKey");
                    depositval = values[i];
                    values[i] = 0, used++;
                    targetval = (depositval / 9) * 8;
                    printf("i.%d %.8f target %.8f\n",i,dstr(depositval),dstr(targetval));
                    if ( (i= LP_nearestvalue(values,n,targetval)) >= 0 )
                    {
                        item = jitem(array,i);
                        txid = jbits256(item,"txid");
                        vout = juint(item,"vout");
                        if ( jstr(item,"scriptPubKey") != 0 && strcmp(script,jstr(item,"scriptPubKey")) == 0 )
                        {
                            value = values[i];
                            values[i] = 0, used++;
                            LP_addutxo(coin,txid,vout,value,deposittxid,depositvout,depositval,script,coinaddr,LP_peerinfos[0].ipaddr,LP_peerinfos[0].port);
                            total += value;
                        }
                    }
                } else break;
            }
            free(values);
        }
        free_json(array);
    }
    free(retstr);
    return(total);
}

cJSON *LP_peerjson(struct LP_peerinfo *peer)
{
    cJSON *item = cJSON_CreateObject();
    jaddstr(item,"ipaddr",peer->ipaddr);
    jaddnum(item,"port",peer->port);
    jaddnum(item,"profit",peer->profitmargin);
    return(item);
}

char *LP_peers()
{
    struct LP_peerinfo *peer,*tmp; cJSON *peersjson = cJSON_CreateArray();
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        jaddi(peersjson,LP_peerjson(peer));
    }
    return(jprint(peersjson,1));
}

struct LP_peerinfo *LP_peerfind(uint32_t ipbits,uint16_t port)
{
    struct LP_peerinfo *peer=0; uint64_t ip_port;
    ip_port = ((uint64_t)port << 32) | ipbits;
    portable_mutex_lock(&LP_mutex);
    HASH_FIND(hh,LP_peerinfos,&ip_port,sizeof(ip_port),peer);
    portable_mutex_unlock(&LP_mutex);
    return(peer);
}

struct LP_peerinfo *_LP_addpeer(uint32_t ipbits,char *ipaddr,uint16_t port,double profitmargin)
{
    struct LP_peerinfo *peer = 0;
    peer = calloc(1,sizeof(*peer));
    memset(peer,0,sizeof(*peer));
    peer->profitmargin = profitmargin;
    peer->ipbits = ipbits;
    strcpy(peer->ipaddr,ipaddr);
    peer->port = port;
    peer->ip_port = ((uint64_t)port << 32) | ipbits;
    portable_mutex_lock(&LP_mutex);
    HASH_ADD(hh,LP_peerinfos,ip_port,sizeof(peer->ip_port),peer);
    LP_numpeers++;
    portable_mutex_unlock(&LP_mutex);
    printf("_LPaddpeer %s -> numpeers.%d\n",ipaddr,LP_numpeers);
    return(peer);
}

struct LP_peerinfo *LP_addpeer(char *ipaddr,uint16_t port,double profitmargin)
{
    uint32_t ipbits; char checkip[64]; struct LP_peerinfo *peer = 0;
    ipbits = (uint32_t)calc_ipbits(ipaddr);
    expand_ipbits(checkip,ipbits);
    if ( strcmp(checkip,ipaddr) == 0 )
    {
        //printf("LPaddpeer %s\n",ipaddr);
        if ( (peer= LP_peerfind(ipbits,port)) != 0 )
        {
            if ( peer->profitmargin == 0. )
                peer->profitmargin = profitmargin;
        } else peer = _LP_addpeer(ipbits,ipaddr,port,profitmargin);
    }
    return(peer);
}

int32_t LP_peersparse(char *destipaddr,uint16_t destport,char *retstr,uint32_t now)
{
    struct LP_peerinfo *peer; uint32_t argipbits; char *argipaddr; uint16_t argport; cJSON *array,*item; int32_t i,n=0;
    if ( (array= cJSON_Parse(retstr)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                if ( (argipaddr= jstr(item,"ipaddr")) != 0 && (argport= juint(item,"port")) != 0 )
                {
                    argipbits = (uint32_t)calc_ipbits(argipaddr);
                    if ( (peer= LP_peerfind(argipbits,argport)) == 0 )
                        peer = LP_addpeer(argipaddr,argport,jdouble(item,"profit"));
                    if ( peer != 0 )
                    {
                        peer->foundtime = now;
                        if ( strcmp(argipaddr,destipaddr) == 0 && destport == argport && peer->numpeers < n )
                            peer->numpeers = n;
                    }
                }
            }
        }
        free_json(array);
    }
    return(n);
}

void LP_peersquery(char *destipaddr,uint16_t destport,char *myipaddr,uint16_t myport,double myprofit)
{
    char *retstr; struct LP_peerinfo *peer,*tmp; uint32_t now,flag = 0;
    peer = LP_peerfind((uint32_t)calc_ipbits(destipaddr),destport);
    if ( peer != 0 && peer->errors > 0 )
        return;
    if ( (retstr= issue_LP_getpeers(destipaddr,destport,myipaddr,myport,myprofit,LP_numpeers)) != 0 )
    {
        now = (uint32_t)time(NULL);
        LP_peersparse(destipaddr,destport,retstr,now);
        free(retstr);
        HASH_ITER(hh,LP_peerinfos,peer,tmp)
        {
            if ( peer->foundtime != now )
            {
                printf("{%s:%u %.6f} ",peer->ipaddr,peer->port,peer->profitmargin);
                flag++;
                if ( (retstr= issue_LP_notify(destipaddr,destport,peer->ipaddr,peer->port,peer->profitmargin,peer->numpeers)) != 0 )
                    free(retstr);
            }
        }
        if ( flag != 0 )
            printf(" <- missing peers\n");
   } else if ( peer != 0 )
       peer->errors++;
}

void LPinit(uint16_t myport,double profitmargin)
{
    char *myipaddr=0; long filesize,n; int32_t i; struct LP_peerinfo *peer,*tmp,*mypeer=0;
    portable_mutex_init(&LP_mutex);
    if ( profitmargin == 0. )
    {
        profitmargin = 0.01;
        printf("default profit margin %f\n",profitmargin);
    }
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)stats_rpcloop,(void *)&myport) != 0 )
    {
        printf("error launching stats rpcloop for port.%u\n",myport);
        exit(-1);
    }
    if ( system("curl -s4 checkip.amazonaws.com > /tmp/myipaddr") == 0 )
    {
        if ( (myipaddr= OS_filestr(&filesize,"/tmp/myipaddr")) != 0 && myipaddr[0] != 0 )
        {
            n = strlen(myipaddr);
            if ( myipaddr[n-1] == '\n' )
                myipaddr[--n] = 0;
            mypeer = LP_addpeer(myipaddr,myport,profitmargin);
            //printf("my ipaddr.(%s) peers.(%s)\n",ipaddr,retstr!=0?retstr:"");
            for (i=0; i<sizeof(default_LPnodes)/sizeof(*default_LPnodes); i++)
            {
                if ( (rand() % 100) > 25 )
                    continue;
                LP_peersquery(default_LPnodes[i],myport,myipaddr,myport,profitmargin);
            }
        }
    }
    if ( myipaddr == 0 )
    {
        printf("couldnt get myipaddr\n");
        exit(-1);
    }
    LP_privkey_init("KMD",60,"test","");
    //printf("peers.(%s)\n",LP_peers());
    while ( 1 )
    {
        if ( mypeer != 0 )
            mypeer->numpeers = LP_numpeers;
        HASH_ITER(hh,LP_peerinfos,peer,tmp)
        {
            if ( peer->numpeers != LP_numpeers )
            {
                printf("%s num.%d vs %d\n",peer->ipaddr,peer->numpeers,LP_numpeers);
                if ( strcmp(peer->ipaddr,myipaddr) != 0 )
                    LP_peersquery(peer->ipaddr,peer->port,myipaddr,myport,profitmargin);
            }
        }
        sleep(LP_numpeers);
    }
}

// Q sending of individual peer that is missing from the other

char *stats_JSON(cJSON *argjson,char *remoteaddr,uint16_t port)
{
    char *method,*ipaddr,*coin,*dest,*retstr = 0; uint16_t argport; int32_t otherpeers; struct LP_peerinfo *peer; cJSON *retjson;
    if ( (method= jstr(argjson,"method")) == 0 )
        return(clonestr("{\"error\":\"need method in request\"}"));
    else
    {
        if ( (ipaddr= jstr(argjson,"ipaddr")) != 0 && (argport= juint(argjson,"port")) != 0 )
        {
            peer = LP_peerfind((uint32_t)calc_ipbits(ipaddr),argport);
            if ( (otherpeers= jint(argjson,"numpeers")) > 0 )
            {
                if ( peer != 0 && peer->numpeers < otherpeers )
                    peer->numpeers = otherpeers;
                else LP_addpeer(ipaddr,argport,jdouble(argjson,"profit"));
            }
            if ( strcmp(method,"getpeers") == 0 )
                retstr = LP_peers();
            else if ( strcmp(method,"notify") == 0 )
                retstr = clonestr("{\"result\":\"success\",\"notify\":\"received\"}");
            else if ( strcmp(method,"getutxos") == 0 && (coin= jstr(argjson,"coin")) != 0 && (dest= jstr(argjson,"dest")) != 0 )
            {
                //retstr = LP_getutxos(coin,dest);
            }
        } else printf("malformed request.(%s)\n",jprint(argjson,0));
    }
    if ( retstr != 0 )
        return(retstr);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"error","unrecognized command");
    return(clonestr(jprint(retjson,1)));
}
