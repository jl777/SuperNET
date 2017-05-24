//
//  LP_unspents.c
//  marketmaker
//
//  Created by Mac on 5/23/17.
//  Copyright © 2017 SuperNET. All rights reserved.
//

#include <stdio.h>

#define LP_PROPAGATION_SLACK 10 // txid ordering is not enforced, so getting extra recent txid

char *default_LPnodes[] = { "5.9.253.195", "5.9.253.196", "5.9.253.197", "5.9.253.198", "5.9.253.199", "5.9.253.200", "5.9.253.201", "5.9.253.202", "5.9.253.203", "5.9.253.204" };
portable_mutex_t LP_peermutex,LP_utxomutex,LP_jsonmutex;
int32_t LP_numpeers,LP_numutxos,LP_mypubsock = -1;

struct LP_peerinfo
{
    UT_hash_handle hh;
    uint64_t ip_port;
    double profitmargin;
    uint32_t ipbits,errortime,errors,numpeers,numutxos,lasttime,connected;
    int32_t pushsock,subsock;
    uint16_t port;
    char ipaddr[64];
} *LP_peerinfos,*LP_mypeer;

struct LP_utxoinfo
{
    UT_hash_handle hh;
    bits256 txid,deposittxid;
    uint64_t satoshis,depositsatoshis;
    int32_t vout,depositvout; uint32_t lasttime,errors;
    double profitmargin;
    char ipaddr[64],coinaddr[64],spendscript[256],coin[16];
    uint16_t port;
} *LP_utxoinfos;

char *nanomsg_tcpname(char *str,char *ipaddr,uint16_t port)
{
    sprintf(str,"tcp://%s:%u",ipaddr,port);
    return(str);
}

int32_t LP_send(int32_t sock,char *msg,int32_t freeflag)
{
    int32_t sentbytes,len,i; struct nn_pollfd pfd;
    for (i=0; i<100; i++)
    {
        pfd.fd = sock;
        pfd.events = NN_POLLOUT;
        if ( nn_poll(&pfd,1,100) > 0 )
        {
            len = (int32_t)strlen(msg) + 1;
            if ( (sentbytes= nn_send(sock,msg,len,0)) != len )
                printf("LP_send sent %d instead of %d\n",sentbytes,len);
            else printf("SENT.(%s)\n",msg);
            if ( freeflag != 0 )
                free(msg);
            return(sentbytes);
        }
        usleep(1000);
    }
    printf("error LP_send\n");
    return(-1);
}

struct LP_peerinfo *LP_peerfind(uint32_t ipbits,uint16_t port)
{
    struct LP_peerinfo *peer=0; uint64_t ip_port;
    ip_port = ((uint64_t)port << 32) | ipbits;
    portable_mutex_lock(&LP_peermutex);
    HASH_FIND(hh,LP_peerinfos,&ip_port,sizeof(ip_port),peer);
    portable_mutex_unlock(&LP_peermutex);
    return(peer);
}

struct LP_utxoinfo *LP_utxofind(bits256 txid)
{
    struct LP_utxoinfo *utxo=0;
    portable_mutex_lock(&LP_utxomutex);
    HASH_FIND(hh,LP_utxoinfos,&txid,sizeof(txid),utxo);
    portable_mutex_unlock(&LP_utxomutex);
    return(utxo);
}

cJSON *LP_peerjson(struct LP_peerinfo *peer)
{
    cJSON *item = cJSON_CreateObject();
    jaddstr(item,"ipaddr",peer->ipaddr);
    jaddnum(item,"port",peer->port);
    jaddnum(item,"profit",peer->profitmargin);
    jaddnum(item,"numpeers",peer->numpeers);
    jaddnum(item,"numutxos",peer->numutxos);
    return(item);
}

cJSON *LP_utxojson(struct LP_utxoinfo *utxo)
{
    struct LP_peerinfo *peer; cJSON *item = cJSON_CreateObject();
    jaddstr(item,"ipaddr",utxo->ipaddr);
    jaddnum(item,"port",utxo->port);
    if ( (peer= LP_peerfind((uint32_t)calc_ipbits(utxo->ipaddr),utxo->port)) != 0 )
    {
        jaddnum(item,"numpeers",peer->numpeers);
        jaddnum(item,"numutxos",peer->numutxos);
    }
    jaddnum(item,"profit",utxo->profitmargin);
    jaddstr(item,"coin",utxo->coin);
    jaddstr(item,"address",utxo->coinaddr);
    jaddstr(item,"script",utxo->spendscript);
    jaddbits256(item,"txid",utxo->txid);
    jaddnum(item,"vout",utxo->vout);
    jaddnum(item,"value",dstr(utxo->satoshis));
    jaddbits256(item,"deposit",utxo->deposittxid);
    jaddnum(item,"dvout",utxo->depositvout);
    jaddnum(item,"dvalue",dstr(utxo->depositsatoshis));
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

char *LP_utxos(char *coin,int32_t lastn)
{
    int32_t i,firsti; struct LP_utxoinfo *utxo,*tmp; cJSON *utxosjson = cJSON_CreateArray();
    i = 0;
    if ( lastn >= LP_numutxos )
        firsti = -1;
    else firsti = (LP_numutxos - lastn);
    HASH_ITER(hh,LP_utxoinfos,utxo,tmp)
    {
        if ( i++ < firsti )
            continue;
        if ( coin == 0 || coin[0] == 0 || strcmp(coin,utxo->coin) == 0 )
        {
            jaddi(utxosjson,LP_utxojson(utxo));
        }
    }
    return(jprint(utxosjson,1));
}

struct LP_peerinfo *LP_addpeer(int32_t mypubsock,char *ipaddr,uint16_t port,uint16_t pushport,uint16_t subport,double profitmargin,int32_t numpeers,int32_t numutxos)
{
    uint32_t ipbits; int32_t pushsock,subsock,timeout; char checkip[64],pushaddr[64],subaddr[64]; struct LP_peerinfo *peer = 0;
    ipbits = (uint32_t)calc_ipbits(ipaddr);
    expand_ipbits(checkip,ipbits);
    if ( strcmp(checkip,ipaddr) == 0 )
    {
        //printf("LPaddpeer %s\n",ipaddr);
        if ( (peer= LP_peerfind(ipbits,port)) != 0 )
        {
            if ( peer->profitmargin == 0. )
                peer->profitmargin = profitmargin;
            if ( numpeers > peer->numpeers )
                peer->numpeers = numpeers;
            if ( numutxos > peer->numutxos )
                peer->numutxos = numutxos;
        }
        else
        {
            peer = calloc(1,sizeof(*peer));
            peer->pushsock = peer->subsock = pushsock = subsock = -1;
            strcpy(peer->ipaddr,ipaddr);
            if ( pushport != 0 && subport != 0 && (pushsock= nn_socket(AF_SP,NN_PUSH)) >= 0 )
            {
                if ( (subsock= nn_socket(AF_SP,NN_SUB)) >= 0 )
                {
                    timeout = 1000;
                    nn_setsockopt(pushsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                    timeout = 1;
                    nn_setsockopt(subsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                    nn_setsockopt(subsock,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
                    peer->pushsock = pushsock;
                    peer->subsock = subsock;
                    nanomsg_tcpname(pushaddr,peer->ipaddr,pushport);
                    nanomsg_tcpname(subaddr,peer->ipaddr,subport);
                    printf("adding (%s and %s) %d %d\n",pushaddr,subaddr,peer->pushsock,peer->subsock);
                    if ( nn_connect(peer->pushsock,pushaddr) >= 0 && nn_connect(peer->subsock,subaddr) >= 0 )
                        peer->connected = (uint32_t)time(NULL);
                } else nn_close(pushsock);
            }
            peer->profitmargin = profitmargin;
            peer->ipbits = ipbits;
            peer->port = port;
            peer->ip_port = ((uint64_t)port << 32) | ipbits;
            portable_mutex_lock(&LP_peermutex);
            HASH_ADD(hh,LP_peerinfos,ip_port,sizeof(peer->ip_port),peer);
            LP_numpeers++;
            portable_mutex_unlock(&LP_peermutex);
            printf("_LPaddpeer %s -> numpeers.%d mypubsock.%d\n",ipaddr,LP_numpeers,mypubsock);
            if ( mypubsock >= 0 )
                LP_send(mypubsock,jprint(LP_peerjson(peer),1),1);
        }
    }
    return(peer);
}

struct LP_utxoinfo *LP_addutxo(struct LP_peerinfo *mypeer,int32_t mypubsock,char *coin,bits256 txid,int32_t vout,int64_t satoshis,bits256 deposittxid,int32_t depositvout,int64_t depositsatoshis,char *spendscript,char *coinaddr,char *ipaddr,uint16_t port,double profitmargin)
{
    struct LP_utxoinfo *utxo = 0;
    if ( coin == 0 || coin[0] == 0 || spendscript == 0 || spendscript[0] == 0 || coinaddr == 0 || coinaddr[0] == 0 || bits256_nonz(txid) == 0 || bits256_nonz(deposittxid) == 0 || vout < 0 || depositvout < 0 || satoshis <= 0 || depositsatoshis <= 0 )
    {
        printf("malformed addutxo %d %d %d %d %d %d %d %d %d %d %d %d\n", coin == 0,coin[0] == 0,spendscript == 0,spendscript[0] == 0,coinaddr == 0,coinaddr[0] == 0,bits256_nonz(txid) == 0,bits256_nonz(deposittxid) == 0,vout < 0,depositvout < 0,satoshis <= 0,depositsatoshis <= 0);
        return(0);
    }
    if ( (utxo= LP_utxofind(txid)) != 0 )
    {
        if ( bits256_cmp(txid,utxo->txid) != 0 || bits256_cmp(deposittxid,utxo->deposittxid) != 0 || vout != utxo->vout || satoshis != utxo->satoshis || depositvout != utxo->depositvout || depositsatoshis != utxo->depositsatoshis || strcmp(coin,utxo->coin) != 0 || strcmp(spendscript,utxo->spendscript) != 0 || strcmp(coinaddr,utxo->coinaddr) != 0 || strcmp(ipaddr,utxo->ipaddr) != 0 || port != utxo->port )
        {
            utxo->errors++;
            char str[65]; printf("error on subsequent utxo add.(%s)\n",bits256_str(str,txid));
        }
        else if ( profitmargin != 0. )
            utxo->profitmargin = profitmargin;
    }
    else
    {
        utxo = calloc(1,sizeof(*utxo));
        utxo->profitmargin = profitmargin;
        strcpy(utxo->ipaddr,ipaddr);
        utxo->port = port;
        safecopy(utxo->coin,coin,sizeof(utxo->coin));
        safecopy(utxo->coinaddr,coinaddr,sizeof(utxo->coinaddr));
        safecopy(utxo->spendscript,spendscript,sizeof(utxo->spendscript));
        utxo->txid = txid;
        utxo->vout = vout;
        utxo->satoshis = satoshis;
        utxo->deposittxid = deposittxid;
        utxo->depositvout = depositvout;
        utxo->depositsatoshis = depositsatoshis;
        portable_mutex_lock(&LP_utxomutex);
        HASH_ADD(hh,LP_utxoinfos,txid,sizeof(txid),utxo);
        LP_numutxos++;
        portable_mutex_unlock(&LP_utxomutex);
        printf("%s:%u LP_addutxo.(%.8f %.8f) numutxos.%d\n",ipaddr,port,dstr(satoshis),dstr(depositsatoshis),LP_numutxos);
        if ( mypubsock >= 0 )
            LP_send(mypubsock,jprint(LP_utxojson(utxo),1),1);
        if ( mypeer != 0 )
            mypeer->numutxos = LP_numutxos;
    }
    return(utxo);
}

int32_t LP_peersparse(int32_t mypubsock,char *destipaddr,uint16_t destport,char *retstr,uint32_t now)
{
    struct LP_peerinfo *peer; uint32_t argipbits; char *argipaddr; uint16_t argport,pushport,subport; cJSON *array,*item; int32_t i,n=0;
    if ( (array= cJSON_Parse(retstr)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                if ( (argipaddr= jstr(item,"ipaddr")) != 0 && (argport= juint(item,"port")) != 0 )
                {
                    if ( (pushport= juint(item,"push")) == 0 )
                        pushport = argport + 1;
                    if ( (subport= juint(item,"sub")) == 0 )
                        subport = argport + 2;
                    argipbits = (uint32_t)calc_ipbits(argipaddr);
                    if ( (peer= LP_peerfind(argipbits,argport)) == 0 )
                        peer = LP_addpeer(mypubsock,argipaddr,argport,pushport,subport,jdouble(item,"profit"),jint(item,"numpeers"),jint(item,"numutxos"));
                    if ( peer != 0 )
                    {
                        peer->lasttime = now;
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

int32_t LP_utxosparse(struct LP_peerinfo *mypeer,int32_t mypubsock,char *destipaddr,uint16_t destport,char *retstr,uint32_t now)
{
    struct LP_peerinfo *peer; uint32_t argipbits; char *argipaddr; uint16_t argport,pushport,subport; cJSON *array,*item; int32_t i,n=0; bits256 txid; struct LP_utxoinfo *utxo;
    if ( (array= cJSON_Parse(retstr)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                if ( (argipaddr= jstr(item,"ipaddr")) != 0 && (argport= juint(item,"port")) != 0 )
                {
                    if ( (pushport= juint(item,"push")) == 0 )
                        pushport = argport + 1;
                    if ( (subport= juint(item,"sub")) == 0 )
                        subport = argport + 2;
                    argipbits = (uint32_t)calc_ipbits(argipaddr);
                    if ( (peer= LP_peerfind(argipbits,argport)) == 0 )
                        peer = LP_addpeer(mypubsock,argipaddr,argport,pushport,subport,jdouble(item,"profit"),jint(item,"numpeers"),jint(item,"numutxos"));
                    if ( jobj(item,"txid") != 0 )
                    {
                        txid = jbits256(item,"txid");
                        utxo = LP_addutxo(mypeer,mypubsock,jstr(item,"coin"),txid,jint(item,"vout"),SATOSHIDEN*jdouble(item,"value"),jbits256(item,"deposit"),jint(item,"dvout"),SATOSHIDEN * jdouble(item,"dvalue"),jstr(item,"script"),jstr(item,"address"),argipaddr,argport,jdouble(item,"profit"));
                        if ( utxo != 0 )
                            utxo->lasttime = now;
                    }
                }
            }
        }
        free_json(array);
    }
    return(n);
}

char *issue_LP_getpeers(char *destip,uint16_t destport,char *ipaddr,uint16_t port,double profitmargin,int32_t numpeers,int32_t numutxos)
{
    char url[512];
    sprintf(url,"http://%s:%u/api/stats/getpeers?ipaddr=%s&port=%u&profit=%.6f&numpeers=%d&numutxos=%d",destip,destport,ipaddr,port,profitmargin,numpeers,numutxos);
    return(issue_curl(url));
}

char *issue_LP_getutxos(char *destip,uint16_t destport,char *coin,int32_t lastn,char *ipaddr,uint16_t port,double profitmargin,int32_t numpeers,int32_t numutxos)
{
    char url[512];
    sprintf(url,"http://%s:%u/api/stats/getutxos?coin=%s&lastn=%d&ipaddr=%s&port=%u&profit=%.6f&numpeers=%d&numutxos=%d",destip,destport,coin,lastn,ipaddr,port,profitmargin,numpeers,numutxos);
    return(issue_curl(url));
}

char *issue_LP_notify(char *destip,uint16_t destport,char *ipaddr,uint16_t port,double profitmargin,int32_t numpeers,int32_t numutxos)
{
    char url[512];
    sprintf(url,"http://%s:%u/api/stats/notify?ipaddr=%s&port=%u&profit=%.6f&numpeers=%d&numutxos=%d",destip,destport,ipaddr,port,profitmargin,numpeers,numutxos);
    return(issue_curl(url));
}

char *issue_LP_notifyutxo(char *destip,uint16_t destport,struct LP_utxoinfo *utxo)
{
    char url[4096],str[65],str2[65];
    sprintf(url,"http://%s:%u/api/stats/notifyutxo?ipaddr=%s&port=%u&profit=%.6f&coin=%s&txid=%s&vout=%d&value=%.8f&deposit=%s&dvout=%d&dvalue=%.8f&script=%s&address=%s",destip,destport,utxo->ipaddr,utxo->port,utxo->profitmargin,utxo->coin,bits256_str(str,utxo->txid),utxo->vout,dstr(utxo->satoshis),bits256_str(str2,utxo->deposittxid),utxo->depositvout,dstr(utxo->depositsatoshis),utxo->spendscript,utxo->coinaddr);
    if ( strlen(url) > 1024 )
        printf("WARNING long url.(%s)\n",url);
    return(issue_curl(url));
}

void LP_peersquery(int32_t mypubsock,char *destipaddr,uint16_t destport,char *myipaddr,uint16_t myport,double myprofit)
{
    char *retstr; struct LP_peerinfo *peer,*tmp; uint32_t now,flag = 0;
    peer = LP_peerfind((uint32_t)calc_ipbits(destipaddr),destport);
    if ( peer != 0 && peer->errors > 0 )
        return;
    if ( (retstr= issue_LP_getpeers(destipaddr,destport,myipaddr,myport,myprofit,LP_numpeers,LP_numutxos)) != 0 )
    {
        printf("got.(%s)\n",retstr);
        now = (uint32_t)time(NULL);
        LP_peersparse(mypubsock,destipaddr,destport,retstr,now);
        free(retstr);
        HASH_ITER(hh,LP_peerinfos,peer,tmp)
        {
            if ( peer->lasttime != now )
            {
                printf("{%s:%u %.6f} ",peer->ipaddr,peer->port,peer->profitmargin);
                flag++;
                if ( (retstr= issue_LP_notify(destipaddr,destport,peer->ipaddr,peer->port,peer->profitmargin,peer->numpeers,0)) != 0 )
                    free(retstr);
            }
        }
        if ( flag != 0 )
            printf(" <- missing peers\n");
    } else if ( peer != 0 )
        peer->errors++;
}

void LP_utxosquery(struct LP_peerinfo *mypeer,int32_t mypubsock,char *destipaddr,uint16_t destport,char *coin,int32_t lastn,char *myipaddr,uint16_t myport,double myprofit)
{
    char *retstr; struct LP_utxoinfo *utxo,*tmp; struct LP_peerinfo *peer; int32_t i,firsti; uint32_t now,flag = 0;
    peer = LP_peerfind((uint32_t)calc_ipbits(destipaddr),destport);
    if ( peer != 0 && peer->errors > 0 )
        return;
    if ( coin == 0 )
        coin = "";
    if ( (retstr= issue_LP_getutxos(destipaddr,destport,coin,lastn,myipaddr,myport,myprofit,LP_numpeers,LP_numutxos)) != 0 )
    {
        now = (uint32_t)time(NULL);
        LP_utxosparse(mypeer,mypubsock,destipaddr,destport,retstr,now);
        free(retstr);
        i = 0;
        if ( lastn >= LP_numutxos )
            firsti = -1;
        else firsti = (LP_numutxos - lastn);
        HASH_ITER(hh,LP_utxoinfos,utxo,tmp)
        {
            if ( i++ < firsti )
                continue;
            if ( utxo->lasttime != now )
            {
                char str[65]; printf("{%s:%u %s} ",utxo->ipaddr,utxo->port,bits256_str(str,utxo->txid));
                flag++;
                if ( (retstr= issue_LP_notifyutxo(destipaddr,destport,utxo)) != 0 )
                    free(retstr);
            }
        }
        if ( flag != 0 )
            printf(" <- missing utxos\n");
    } else if ( peer != 0 )
        peer->errors++;
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

uint64_t LP_privkey_init(struct LP_peerinfo *mypeer,int32_t mypubsock,char *coin,uint8_t addrtype,char *passphrase,char *wifstr)
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
                            LP_addutxo(mypeer,mypubsock,coin,txid,vout,value,deposittxid,depositvout,depositval,script,coinaddr,LP_peerinfos[0].ipaddr,LP_peerinfos[0].port,LP_peerinfos[0].profitmargin);
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

char *stats_JSON(cJSON *argjson,char *remoteaddr,uint16_t port)
{
    char *method,*ipaddr,*coin,*retstr = 0; uint16_t argport,pushport,subport; int32_t otherpeers,othernumutxos; struct LP_peerinfo *peer; cJSON *retjson;
    if ( (method= jstr(argjson,"method")) == 0 )
        return(clonestr("{\"error\":\"need method in request\"}"));
    else
    {
        portable_mutex_lock(&LP_jsonmutex);
        if ( (ipaddr= jstr(argjson,"ipaddr")) != 0 && (argport= juint(argjson,"port")) != 0 )
        {
            if ( (pushport= juint(argjson,"push")) == 0 )
                pushport = argport + 1;
            if ( (subport= juint(argjson,"sub")) == 0 )
                subport = argport + 2;
            if ( (peer= LP_peerfind((uint32_t)calc_ipbits(ipaddr),argport)) != 0 )
            {
                if ( (otherpeers= jint(argjson,"numpeers")) > peer->numpeers )
                    peer->numpeers = otherpeers;
                if ( (othernumutxos= jint(argjson,"numutxos")) > peer->numutxos )
                    peer->numutxos = othernumutxos;
            } else LP_addpeer(LP_mypubsock,ipaddr,argport,pushport,subport,jdouble(argjson,"profit"),jint(argjson,"numpeers"),jint(argjson,"numutxos"));
            if ( strcmp(method,"getpeers") == 0 )
                retstr = LP_peers();
            else if ( strcmp(method,"getutxos") == 0 && (coin= jstr(argjson,"coin")) != 0 )
                retstr = LP_utxos(coin,jint(argjson,"lastn"));
            else if ( strcmp(method,"notify") == 0 )
                retstr = clonestr("{\"result\":\"success\",\"notify\":\"received\"}");
            else if ( strcmp(method,"notifyutxo") == 0 )
            {
                printf("utxonotify.(%s)\n",jprint(argjson,0));
                LP_addutxo(LP_mypeer,LP_mypubsock,jstr(argjson,"coin"),jbits256(argjson,"txid"),jint(argjson,"vout"),SATOSHIDEN * jdouble(argjson,"value"),jbits256(argjson,"deposit"),jint(argjson,"dvout"),SATOSHIDEN * jdouble(argjson,"dvalue"),jstr(argjson,"script"),jstr(argjson,"address"),ipaddr,argport,jdouble(argjson,"profit"));
                retstr = clonestr("{\"result\":\"success\",\"notifyutxo\":\"received\"}");
            }
        } else printf("malformed request.(%s)\n",jprint(argjson,0));
        portable_mutex_unlock(&LP_jsonmutex);
    }
    if ( retstr != 0 )
        return(retstr);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"error","unrecognized command");
    return(clonestr(jprint(retjson,1)));
}

void LPinit(uint16_t myport,uint16_t mypull,uint16_t mypub,double profitmargin)
{
    char *myipaddr=0,*retstr; long filesize,n; int32_t timeout,maxsize,recvsize,nonz,i,lastn,pullsock=-1,pubsock=-1; struct LP_peerinfo *peer,*tmp,*mypeer=0; char pushaddr[128],subaddr[128]; void *ptr; cJSON *argjson;
    portable_mutex_init(&LP_peermutex);
    portable_mutex_init(&LP_utxomutex);
    portable_mutex_init(&LP_jsonmutex);
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
            pullsock = pubsock = -1;
            nanomsg_tcpname(pushaddr,myipaddr,mypull);
            nanomsg_tcpname(subaddr,myipaddr,mypub);
            printf(">>>>>>>>> myipaddr.%s (%s %s)\n",myipaddr,pushaddr,subaddr);
            if ( (pullsock= nn_socket(AF_SP,NN_PULL)) >= 0 && (pubsock= nn_socket(AF_SP,NN_PUB)) >= 0 )
            {
                if ( nn_bind(pullsock,pushaddr) >= 0 && nn_bind(pubsock,subaddr) >= 0 )
                {
                    timeout = 10;
                    nn_setsockopt(pubsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                    timeout = 1;
                    nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                    timeout = 1;
                    maxsize = 1024 * 1024;
                    nn_setsockopt(pullsock,NN_SOL_SOCKET,NN_RCVBUF,&maxsize,sizeof(maxsize));
                }
                else
                {
                    printf("error binding to (%s).%d (%s).%d\n",pushaddr,pullsock,subaddr,pubsock);
                    if ( pullsock >= 0 )
                        nn_close(pullsock), pullsock = -1;
                    if ( pubsock >= 0 )
                        nn_close(pubsock), pubsock = -1;
                }
            } else printf("error getting sockets %d %d\n",pullsock,pubsock);
            LP_mypubsock = pubsock;
            LP_mypeer = mypeer = LP_addpeer(pubsock,myipaddr,myport,0,0,profitmargin,LP_numpeers,LP_numutxos);
            //printf("my ipaddr.(%s) peers.(%s)\n",ipaddr,retstr!=0?retstr:"");
            for (i=0; i<sizeof(default_LPnodes)/sizeof(*default_LPnodes); i++)
            {
                if ( (rand() % 100) > 25 )
                    continue;
                LP_peersquery(pubsock,default_LPnodes[i],myport,myipaddr,myport,profitmargin);
            }
        } else printf("error getting myipaddr\n");
    } else printf("error issuing curl\n");
    if ( myipaddr == 0 )
    {
        printf("couldnt get myipaddr\n");
        exit(-1);
    }
    LP_privkey_init(mypeer,pubsock,"KMD",60,"test","");
    printf("utxos.(%s)\n",LP_utxos("",10000));
    while ( 1 )
    {
        nonz = 0;
        if ( mypeer != 0 )
        {
            mypeer->numpeers = LP_numpeers;
            if ( mypeer->numutxos != LP_numutxos )
                printf("numutxos %d -> %d\n",mypeer->numutxos,LP_numutxos);
            mypeer->numutxos = LP_numutxos;
        }
        HASH_ITER(hh,LP_peerinfos,peer,tmp)
        {
            if ( peer->numpeers != LP_numpeers )
            {
                printf("%s num.%d vs %d\n",peer->ipaddr,peer->numpeers,LP_numpeers);
                if ( strcmp(peer->ipaddr,myipaddr) != 0 )
                    LP_peersquery(pubsock,peer->ipaddr,peer->port,myipaddr,myport,profitmargin);
            }
            if ( peer->numutxos != LP_numutxos )
            {
                lastn = peer->numutxos - LP_numutxos + LP_PROPAGATION_SLACK;
                if ( lastn < 0 )
                    lastn = LP_PROPAGATION_SLACK * 2;
                printf("%s numutxos.%d vs %d lastn.%d\n",peer->ipaddr,peer->numutxos,LP_numutxos,lastn);
                if ( strcmp(peer->ipaddr,myipaddr) != 0 )
                    LP_utxosquery(mypeer,pubsock,peer->ipaddr,peer->port,"",lastn,myipaddr,myport,profitmargin);
            }
            while ( peer->subsock >= 0 && (recvsize= nn_recv(peer->subsock,&ptr,NN_MSG,0)) >= 0 )
            {
                nonz++;
                if ( (argjson= cJSON_Parse((char *)ptr)) != 0 )
                {
                    if ( (retstr= stats_JSON(argjson,"127.0.0.1",mypub)) != 0 )
                    {
                        printf("%s RECV.[%d] %s\n",peer->ipaddr,recvsize,(char *)ptr);
                        free(retstr);
                    }
                    free_json(argjson);
                } else printf("error parsing.(%s)\n",(char *)ptr);
                if ( ptr != 0 )
                    nn_freemsg(ptr), ptr = 0;
            }
        }
        while ( pullsock >= 0 && (recvsize= nn_recv(pullsock,&ptr,NN_MSG,0)) >= 0 )
        {
            nonz++;
            printf("PULL.[%d] %s\n",recvsize,(char *)ptr);
            if ( ptr != 0 )
                nn_freemsg(ptr), ptr = 0;
        }
       if ( nonz == 0 )
            sleep(LP_numpeers);
    }
}

#ifdef __APPLE__
int32_t nn_bind() { return(-1); }
int32_t nn_close() { return(-1); }
int32_t nn_connect() { return(-1); }
int32_t nn_freemsg() { return(-1); }
int32_t nn_poll() { return(-1); }
int32_t nn_recv() { return(-1); }
int32_t nn_send() { return(-1); }
int32_t nn_setsockopt() { return(-1); }
int32_t nn_socket() { return(-1); }

#endif
