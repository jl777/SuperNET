//
//  LP_unspents.c
//  marketmaker
//
//  Created by Mac on 5/23/17.
//  Copyright © 2017 SuperNET. All rights reserved.
//

#include <stdio.h>

char *default_LPnodes[] = { "5.9.253.195", "5.9.253.196", "5.9.253.197", "5.9.253.198", "5.9.253.199", "5.9.253.200", "5.9.253.201", "5.9.253.202", "5.9.253.203", "5.9.253.204" };

struct LP_peerinfo
{
    double profitmargin;
    uint32_t ipbits,gotintro,sentintro;
    char ipaddr[64];
    uint16_t port;
} LP_peerinfos[1024];
int32_t LP_numpeers;

void LP_addutxo(char *coin,bits256 txid,int32_t vout,uint64_t satoshis,bits256 deposittxid,int32_t depositvout,uint64_t depositsatoshis,char *spendscript,char *coinaddr)
{
    printf("LP_addutxo.(%.8f %.8f)\n",dstr(satoshis),dstr(depositsatoshis));
}

void _LP_addpeer(int32_t i,uint32_t ipbits,char *ipaddr,uint16_t port,uint32_t gotintro,uint32_t sentintro,double profitmargin)
{
    struct LP_peerinfo *peer;
    if ( i == sizeof(LP_peerinfos)/sizeof(*LP_peerinfos) )
        i = (rand() % (sizeof(LP_peerinfos)/sizeof(*LP_peerinfos)));
    peer = &LP_peerinfos[i];
    memset(peer,0,sizeof(*peer));
    peer->profitmargin = profitmargin;
    peer->ipbits = ipbits;
    peer->gotintro = gotintro;
    peer->sentintro = sentintro;
    strcpy(peer->ipaddr,ipaddr);
    peer->port = port;
    if ( i == LP_numpeers )
        LP_numpeers++;
}

void LP_notify(struct LP_peerinfo *peer,char *ipaddr,uint16_t port)
{
    char buf[1024],*retstr,*argipaddr; uint32_t ipbits; cJSON *array,*item; int32_t i,j,n; uint16_t argport; double profit;
    sprintf(buf,"http://%s:%u/api/stats/intro?ipaddr=%s&port=%u",peer->ipaddr,peer->port,ipaddr,port);
    if ( (retstr= issue_curl(buf)) != 0 )
    {
        printf("got (%s) from (%s)\n",retstr,buf);
        if ( (array= cJSON_Parse(retstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( (argipaddr= jstr(item,"ipaddr")) != 0 && jobj(item,"port") != 0 && (profit=jdouble(item,"profit")) > 0. )
                    {
                        argport = juint(item,"port");
                        ipbits = (uint32_t)calc_ipbits(argipaddr);
                        for (j=0; j<LP_numpeers; j++)
                            if ( LP_peerinfos[j].ipbits == ipbits && LP_peerinfos[j].port == argport )
                                break;
                        if ( j == LP_numpeers )
                            _LP_addpeer(j,ipbits,argipaddr,argport,0,0,profit);
                    }
                }
            }
            free_json(array);
        }
        free(retstr);
    }
}

cJSON *LP_peerjson(struct LP_peerinfo *peer)
{
    cJSON *item = cJSON_CreateObject();
    jaddstr(item,"ipaddr",peer->ipaddr);
    jaddnum(item,"port",peer->port);
    return(item);
}

char *LP_peers()
{
    int32_t i; cJSON *peersjson = cJSON_CreateArray();
    for (i=0; i<LP_numpeers; i++)
        jaddi(peersjson,LP_peerjson(&LP_peerinfos[i]));
    return(jprint(peersjson,1));
}

char *LP_addpeer(char *ipaddr,uint16_t port,uint32_t gotintro,uint32_t sentintro,double profitmargin)
{
    uint32_t i,j,lastj,iter,ipbits; char checkip[64]; struct LP_peerinfo *peer;
    ipbits = (uint32_t)calc_ipbits(ipaddr);
    expand_ipbits(checkip,ipbits);
    if ( strcmp(checkip,ipaddr) == 0 )
    {
        for (i=0; i<LP_numpeers; i++)
            if ( LP_peerinfos[i].ipbits == ipbits && LP_peerinfos[i].port == port )
                break;
        if ( i == LP_numpeers )
        {
            if ( LP_numpeers > 0 )
            {
                lastj = -1;
                for (iter=0; iter<2; iter++)
                {
                    j = (rand() % LP_numpeers);
                    if ( j != lastj )
                    {
                        peer = &LP_peerinfos[j];
                        if ( peer->sentintro == 0 )
                            LP_notify(peer,ipaddr,port);
                        lastj = j;
                    }
                }
            }
            _LP_addpeer(i,ipbits,ipaddr,port,gotintro,sentintro,profitmargin);
        }
    }
    return(LP_peers());
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
                            LP_addutxo(coin,txid,vout,value,deposittxid,depositvout,depositval,script,coinaddr);
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

void LPinit(uint16_t port,double profitmargin)
{
    char *retstr,*ipaddr; long filesize,n; int32_t i;
    if ( system("curl -s4 checkip.amazonaws.com > /tmp/myipaddr") == 0 )
    {
        if ( (ipaddr= OS_filestr(&filesize,"/tmp/myipaddr")) != 0 && ipaddr[0] != 0 )
        {
            n = strlen(ipaddr);
            if ( ipaddr[n-1] == '\n' )
                ipaddr[--n] = 0;
            retstr = LP_addpeer(ipaddr,port,0,(uint32_t)time(NULL),profitmargin);
            printf("my ipaddr.(%s) peers.(%s)\n",ipaddr,retstr!=0?retstr:"");
            if ( retstr != 0 )
                free(retstr);
            for (i=0; i<sizeof(default_LPnodes)/sizeof(*default_LPnodes); i++)
            {
                if ( (retstr= issue_LP_intro(default_LPnodes[i],port,ipaddr,port,0.01)) != 0 )
                {
                    printf("(%s) -> %s\n",default_LPnodes[i],retstr);
                    free(retstr);
                }
            }
        }
    }
    LP_privkey_init("KMD",60,"test","");
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)stats_rpcloop,(void *)&port) != 0 )
    {
        printf("error launching stats rpcloop for port.%u\n",port);
        exit(-1);
    }
    getchar();
}

char *stats_JSON(cJSON *argjson,char *remoteaddr,uint16_t port)
{
    char *method,*ipaddr,*coin,*dest,*retstr = 0; uint16_t argport; double profitmargin;
    if ( (method= jstr(argjson,"method")) == 0 )
        return(clonestr("{\"error\":\"need method in request\"}"));
    else
    {
        if ( strcmp(method,"intro") == 0 )
        {
            if ( (ipaddr= jstr(argjson,"ipaddr")) != 0 && (argport= juint(argjson,"port")) != 0 && (profitmargin= jdouble(argjson,"profit")) != 0. )
                retstr = LP_addpeer(ipaddr,argport,(uint32_t)time(NULL),0,profitmargin);
        }
        else if ( strcmp(method,"getpeers") == 0 )
            retstr = LP_peers();
        else if ( strcmp(method,"getutxos") == 0 && (coin= jstr(argjson,"coin")) != 0 && (dest= jstr(argjson,"dest")) != 0 )
        {
            //retstr = LP_getutxos(coin,dest);
        }
    }
    if ( retstr != 0 )
        return(retstr);
    return(clonestr(jprint(argjson,0)));
}
