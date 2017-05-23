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
    double profitmargin,notify_margin;
    uint32_t ipbits,gotintro,sentintro,errortime,errors,numpeers,notify_numpeers;
    char ipaddr[64],notify_ipaddr[64];
    uint16_t port,notify_port;
} LP_peerinfos[1024];
int32_t LP_numpeers;

void LP_addutxo(char *coin,bits256 txid,int32_t vout,uint64_t satoshis,bits256 deposittxid,int32_t depositvout,uint64_t depositsatoshis,char *spendscript,char *coinaddr,char *ipaddr,uint16_t port)
{
    printf("%s:%u LP_addutxo.(%.8f %.8f)\n",ipaddr,port,dstr(satoshis),dstr(depositsatoshis));
}

struct LP_peerinfo *LP_peerfind(uint32_t ipbits,uint16_t port)
{
    int32_t j;
    for (j=0; j<LP_numpeers; j++)
        if ( LP_peerinfos[j].ipbits == ipbits && LP_peerinfos[j].port == port )
        {
            //printf("(%s) already in slot.%d\n",argipaddr,j);
            return(&LP_peerinfos[j]);
        }
    return(0);
}

void _LP_addpeer(int32_t i,uint32_t ipbits,char *ipaddr,uint16_t port,uint32_t gotintro,uint32_t sentintro,double profitmargin)
{
    struct LP_peerinfo *peer;
    if ( i == sizeof(LP_peerinfos)/sizeof(*LP_peerinfos) )
        i = (rand() % (sizeof(LP_peerinfos)/sizeof(*LP_peerinfos)));
    else LP_numpeers++;
    peer = &LP_peerinfos[i];
    memset(peer,0,sizeof(*peer));
    peer->profitmargin = profitmargin;
    peer->ipbits = ipbits;
    peer->gotintro = gotintro;
    peer->sentintro = sentintro;
    strcpy(peer->ipaddr,ipaddr);
    peer->port = port;
    printf("_LPaddpeer %s -> i.%d numpeers.%d\n",ipaddr,i,LP_numpeers);
}

void LP_notify(struct LP_peerinfo *peer,char *ipaddr,uint16_t port,double profit,int32_t numpeers,char *retstr)
{
    char buf[1024],*argipaddr; uint32_t ipbits; cJSON *array,*item; int32_t i,n; uint16_t argport;
    sprintf(buf,"http://%s:%u/api/stats/intro?ipaddr=%s&port=%u&profit=%.6f&numpeers=%d",peer->ipaddr,peer->port,ipaddr,port,profit,numpeers);
    if ( retstr != 0 || (retstr= issue_curl(buf)) != 0 )
    {
        //printf("got (%s) from (%s)\n",retstr,buf);
        if ( (array= cJSON_Parse(retstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                peer->numpeers = n;
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( (argipaddr= jstr(item,"ipaddr")) != 0 && jobj(item,"port") != 0 )
                    {
                        argport = juint(item,"port");
                        ipbits = (uint32_t)calc_ipbits(argipaddr);
                        if ( LP_peerfind(ipbits,argport) == 0 )
                            _LP_addpeer(LP_numpeers,ipbits,argipaddr,argport,0,0,jdouble(item,"profit"));
                    }
                }
            }
            free_json(array);
        }
        free(retstr);
    } else peer->errors++, peer->errortime = (uint32_t)time(NULL);
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
    int32_t i; cJSON *peersjson = cJSON_CreateArray();
    for (i=0; i<LP_numpeers; i++)
        if ( LP_peerinfos[i].errors == 0 )
            jaddi(peersjson,LP_peerjson(&LP_peerinfos[i]));
    return(jprint(peersjson,1));
}

char *LP_addpeer(char *ipaddr,uint16_t port,uint32_t gotintro,uint32_t sentintro,double profitmargin)
{
    uint32_t j,ipbits; char checkip[64]; struct LP_peerinfo *peer;
    ipbits = (uint32_t)calc_ipbits(ipaddr);
    expand_ipbits(checkip,ipbits);
    if ( strcmp(checkip,ipaddr) == 0 )
    {
        //printf("LPaddpeer %s\n",ipaddr);
        if ( (peer= LP_peerfind(ipbits,port)) != 0 )
        {
            if ( peer->profitmargin == 0. )
                peer->profitmargin = profitmargin;
            if ( gotintro != 0 )
                peer->gotintro = gotintro;
            //if ( peer->errors == 0 )
            {
                j = rand() % LP_numpeers;
                peer = &LP_peerinfos[j];
                //printf("queue notify (%s) from (%s)\n",peer->ipaddr,ipaddr);
                peer->notify_margin = LP_peerinfos[0].profitmargin;
                peer->notify_numpeers = LP_numpeers;
                peer->notify_port = LP_peerinfos[0].port;
                strcpy(peer->notify_ipaddr,LP_peerinfos[0].ipaddr);
            }
        }
        else
        {
            for (j=0; j<LP_numpeers; j++)
            {
                peer = &LP_peerinfos[j];
                //printf("queue notify (%s) from (%s)\n",peer->ipaddr,ipaddr);
                peer->notify_margin = LP_peerinfos[0].profitmargin;
                peer->notify_numpeers = LP_numpeers;
                peer->notify_port = port;
                strcpy(peer->notify_ipaddr,ipaddr);
            }
            _LP_addpeer(LP_numpeers,ipbits,ipaddr,port,gotintro,sentintro,profitmargin);
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

void LPinit(uint16_t port,double profitmargin)
{
    char *retstr,*ipaddr,tmp[64]; long filesize,n; int32_t i,notifynumpeers; uint16_t argport; struct LP_peerinfo *peer; double notifymargin;
    if ( profitmargin == 0. )
    {
        profitmargin = 0.01;
        printf("default profit margin %f\n",profitmargin);
    }
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)stats_rpcloop,(void *)&port) != 0 )
    {
        printf("error launching stats rpcloop for port.%u\n",port);
        exit(-1);
    }
    if ( system("curl -s4 checkip.amazonaws.com > /tmp/myipaddr") == 0 )
    {
        if ( (ipaddr= OS_filestr(&filesize,"/tmp/myipaddr")) != 0 && ipaddr[0] != 0 )
        {
            n = strlen(ipaddr);
            if ( ipaddr[n-1] == '\n' )
                ipaddr[--n] = 0;
            retstr = LP_addpeer(ipaddr,port,0,(uint32_t)time(NULL),profitmargin);
            LP_peerinfos[0].profitmargin = profitmargin;
            //printf("my ipaddr.(%s) peers.(%s)\n",ipaddr,retstr!=0?retstr:"");
            if ( retstr != 0 )
                free(retstr);
            for (i=0; i<sizeof(default_LPnodes)/sizeof(*default_LPnodes); i++)
            {
                if ( (rand() % 100) > 25 )
                    continue;
                if ( (retstr= issue_LP_intro(default_LPnodes[i],port,ipaddr,port,profitmargin,LP_numpeers)) != 0 )
                {
                    //printf("(%s) -> %s\n",default_LPnodes[i],retstr);
                    LP_notify(&LP_peerinfos[i],ipaddr,port,0,0,retstr);
                    //free(retstr);
                }
            }
        }
    }
    LP_privkey_init("KMD",60,"test","");
    //printf("peers.(%s)\n",LP_peers());
    while ( 1 )
    {
        for (i=1; i<LP_numpeers; i++)
        {
            peer = &LP_peerinfos[i];
            if ( peer->numpeers != LP_numpeers && (peer->notify_ipaddr[0] == 0 || peer->notify_port == 0) )
            {
                strcpy(peer->notify_ipaddr,LP_peerinfos[0].ipaddr);
                peer->notify_port = LP_peerinfos[0].port;
                peer->notify_margin = LP_peerinfos[0].profitmargin;
                peer->notify_numpeers = LP_numpeers;
                printf("LP_numpeers.%d != [%d] (%s).%d\n",LP_numpeers,i,peer->ipaddr,peer->numpeers);
            }
            if ( peer->notify_ipaddr[0] != 0 && peer->notify_port != 0 )
            {
                strcpy(tmp,peer->notify_ipaddr);
                argport = peer->notify_port;
                notifymargin = peer->notify_margin;
                notifynumpeers = peer->notify_numpeers;
                peer->notify_port = 0;
                peer->notify_margin = 0;
                peer->notify_numpeers = 0;
                memset(peer->notify_ipaddr,0,sizeof(peer->notify_ipaddr));
                //if ( (peer->errors == 0 || (time(NULL) - peer->errortime) > 3600) )
                    LP_notify(peer,tmp,argport,notifymargin,notifynumpeers,0);
            }
        }
        if ( (rand() % 10) == 0 && LP_numpeers > 0 )
        {
            i = rand() % LP_numpeers;
            peer = &LP_peerinfos[i];
            if ( i > 0 )//&& (peer->errors == 0 || (time(NULL) - peer->errortime) > 3600) )
            {
                if ( (retstr= issue_LP_getpeers(peer->ipaddr,peer->port,LP_peerinfos[0].ipaddr,LP_peerinfos[0].port,LP_peerinfos[0].profitmargin,LP_numpeers)) != 0 )
                {
                    LP_notify(peer,peer->ipaddr,peer->port,0,0,retstr);
                    //free(retstr);
                } else peer->errors++, peer->errortime = (uint32_t)time(NULL);
            }
        }
        sleep(6);
    }
}

char *stats_JSON(cJSON *argjson,char *remoteaddr,uint16_t port)
{
    char *method,*ipaddr,*coin,*dest,*retstr = 0; uint16_t argport; int32_t otherpeers; struct LP_peerinfo *peer;
    if ( (method= jstr(argjson,"method")) == 0 )
        return(clonestr("{\"error\":\"need method in request\"}"));
    else
    {
        printf("got (%s)\n",jprint(argjson,0));
        if ( (otherpeers= jint(argjson,"numpeers")) > 0 )
        {
            if ( (ipaddr= jstr(argjson,"ipaddr")) != 0 && (argport= juint(argjson,"port")) != 0 )
            {
                printf("peer.(%s:%u) numpeers.%d != LP_numpeers.%d (%s)\n",ipaddr,argport,otherpeers,LP_numpeers,jprint(argjson,0));
                if ( (peer= LP_peerfind((uint32_t)calc_ipbits(ipaddr),argport)) != 0 )
                {
                    printf("found peer.(%s:%u)\n",ipaddr,argport);
                    peer->numpeers = otherpeers;
                    if ( otherpeers != LP_numpeers )
                    {
                        peer->notify_port = port;
                        peer->notify_numpeers = otherpeers;
                        peer->notify_margin = jdouble(argjson,"profit");
                        strcpy(peer->notify_ipaddr,ipaddr);
                    }
                }
            }
        }
        if ( strcmp(method,"intro") == 0 )
        {
            if ( (ipaddr= jstr(argjson,"ipaddr")) != 0 && (argport= juint(argjson,"port")) != 0 )
                retstr = LP_addpeer(ipaddr,argport,(uint32_t)time(NULL),0,jdouble(argjson,"profit"));
        }
        else if ( strcmp(method,"getpeers") == 0 && (ipaddr= jstr(argjson,"ipaddr")) != 0 && (argport= juint(argjson,"port")) != 0 )
            retstr = LP_addpeer(ipaddr,argport,(uint32_t)time(NULL),0,jdouble(argjson,"profit"));
        else if ( strcmp(method,"getutxos") == 0 && (coin= jstr(argjson,"coin")) != 0 && (dest= jstr(argjson,"dest")) != 0 )
        {
            //retstr = LP_getutxos(coin,dest);
        }
    }
    if ( retstr != 0 )
        return(retstr);
    return(clonestr(jprint(argjson,0)));
}
