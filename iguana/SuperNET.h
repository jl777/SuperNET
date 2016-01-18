/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
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

#ifndef INCLUDED_SUPERNET_H
#define INCLUDED_SUPERNET_H

#include "../crypto777/OS_portable.h"
#include "../includes/cJSON.h"
#include "../crypto777/nanosrc/nn.h"

#define SUPERNET_LBPORT 7770
#define SUPERNET_PUBPORT 7771
#define SUPERNET_PORTP2P 7770
#define SUPERNET_NETWORKTIMEOUT 10000
#define SUPERNET_POLLTIMEOUT 1
#define SUPERNET_APIUSLEEP (SUPERNET_POLLTIMEOUT * 10000)
#define SUPERNET_MAXAGENTS 64
#define NXT_TOKEN_LEN 160
#define nn_errstr() nn_strerror(nn_errno())
#define MAX_SERVERNAME 128
#define SUPERNET_MAXRECVBUF (1024 * 1024 * 16)
#define SUPERNET_PINGGAP 6

#define SUPERNET_FORWARD 2
#define SUPERNET_ISMINE 1
#define SUPERNET_MAXDELAY (1000 * 3600)
#define SUPERNET_APIVERSION 0

/*#define LB_OFFSET 1
#define PUBGLOBALS_OFFSET 2
#define PUBRELAYS_OFFSET 3


#define MAX_SERVERNAME 128
struct relayargs
{
    char name[16],endpoint[MAX_SERVERNAME];
    int32_t sock,type,bindflag,sendtimeout,recvtimeout;
};
struct relay_info { int32_t sock,num,mytype,desttype; struct endpoint connections[1 << CONNECTION_NUMBITS]; };*/

#define CONNECTION_NUMBITS 10
struct endpoint { queue_t nnrecvQ; int32_t nnsock,nnind; uint32_t ipbits; uint16_t port,directind; uint8_t transport,nn; };

struct direct_connection { char handler[16]; struct endpoint epbits; int32_t sock; };

struct supernet_msghdr
{
    bits256 dest,sender,arg;
    uint8_t type,serlen[3],ser_nonce[4],ser_timestamp[4],ser_duration[4];
    char agent[8],coin[5],func;
    uint8_t data[];
};

struct supernet_agent
{
    struct queueitem DL; queue_t recvQ; uint64_t totalrecv,totalsent;
    int32_t (*recvfunc)(void *myinfo,struct supernet_agent *,struct supernet_msghdr *msg,uint8_t *data,int32_t datalen);
    cJSON *networks;
    char name[9],ipaddr[64],reppoint[64],pubpoint[64]; int32_t reqsock,repsock,pubsock,subsock;
    uint32_t ipbits,dead; int32_t num,sock; uint16_t port,pubport,repport;
};

struct supernet_address
{
    bits256 pubkey,iphash;
    uint32_t selfipbits,myipbits; int32_t confirmed,totalconfirmed;
};

struct supernet_info
{
    char ipaddr[64],transport[8]; int32_t APISLEEP; int32_t iamrelay;
    int32_t Debuglevel,readyflag,dead,POLLTIMEOUT; char rpcsymbol[16],LBpoint[64],PUBpoint[64];
    //int32_t pullsock,subclient,lbclient,lbserver,servicesock,pubglobal,pubrelays,numservers;
    bits256 privkey;
    uint8_t *recvbuf[6];
    struct supernet_address myaddr;
    int32_t LBsock,PUBsock,reqsock,subsock,networktimeout,maxdelay;
    uint16_t LBport,PUBport,reqport,subport;
    struct nn_pollfd pfd[SUPERNET_MAXAGENTS]; //struct relay_info active;
    struct supernet_agent agents[SUPERNET_MAXAGENTS]; queue_t acceptQ; int32_t numagents;
};

struct supernet_endpoint
{
    char name[64]; struct endpoint ep;
    int32_t (*nnrecvfunc)(struct supernet_info *,struct supernet_endpoint *,int32_t ind,uint8_t *msg,int32_t nnlen);
    queue_t nnrecvQ;
    int32_t nnsock,num; struct endpoint eps[];
};

void expand_epbits(char *endpoint,struct endpoint epbits);
struct endpoint calc_epbits(char *transport,uint32_t ipbits,uint16_t port,int32_t type);

struct supernet_info *SuperNET_MYINFO(char *passphrase);
void SuperNET_init(void *args);
char *SuperNET_JSON(struct supernet_info *myinfo,cJSON *json,char *remoteaddr);

char *SuperNET_jsonstr(struct supernet_info *myinfo,char *jsonstr,char *remoteaddr);
char *SuperNET_DHTencode(struct supernet_info *myinfo,char *destip,bits256 destpub,char *hexmsg,int32_t maxdelay,int32_t broadcastflag);
char *SuperNET_parser(struct supernet_info *myinfo,char *agent,char *method,cJSON *json,char *remoteaddr);
char *SuperNET_processJSON(struct supernet_info *myinfo,cJSON *json,char *remoteaddr);
char *SuperNET_DHTsend(struct supernet_info *myinfo,bits256 routehash,char *hexmessage,int32_t maxdelay,int32_t broadcastflag);
uint16_t SuperNET_API2num(char *agent,char *method);
int32_t SuperNET_num2API(char *agent,char *method,uint16_t num);
bits256 SuperNET_sharedseed(struct supernet_info *myinfo,bits256 otherpub);


#endif

