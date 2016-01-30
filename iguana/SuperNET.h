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

#ifndef INCLUDED_SUPERNET_H
#define INCLUDED_SUPERNET_H

#define SUPERNET_MAXHOPS 7
#include "../crypto777/OS_portable.h"
#include "../includes/cJSON.h"
#include "../crypto777/nanosrc/nn.h"

#define SUPERNET_GETPEERSTR "{\"agent\":\"SuperNET\",\"method\":\"getpeers\",\"plaintext\":1}"
#define SUPERNET_STOPSTR "{\"agent\":\"SuperNET\",\"method\":\"stop\",\"plaintext\":1}"

#define SUPERNET_MAXEXCHANGES 64
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
#define SUPERNET_MAXTIMEDIFF 10

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
    bits256 pubkey,iphash,persistent;
    uint32_t selfipbits,myipbits; int32_t confirmed,totalconfirmed; uint64_t nxt64bits;
    char NXTADDR[32];
};

struct supernet_info
{
    char ipaddr[64],transport[8]; int32_t APISLEEP; int32_t iamrelay;
    int32_t Debuglevel,readyflag,dead,POLLTIMEOUT; char rpcsymbol[16],LBpoint[64],PUBpoint[64];
    //int32_t pullsock,subclient,lbclient,lbserver,servicesock,pubglobal,pubrelays,numservers;
    bits256 privkey,persistent_priv;
    uint8_t *recvbuf[6];
    struct supernet_address myaddr;
    int32_t LBsock,PUBsock,reqsock,subsock,networktimeout,maxdelay;
    uint16_t LBport,PUBport,reqport,subport;
    struct nn_pollfd pfd[SUPERNET_MAXAGENTS]; //struct relay_info active;
    struct supernet_agent agents[SUPERNET_MAXAGENTS]; queue_t acceptQ; int32_t numagents,numexchanges;
    struct exchange_info *tradingexchanges[SUPERNET_MAXEXCHANGES];
};

/*struct supernet_endpoint
{
    char name[64]; struct endpoint ep;
    int32_t (*nnrecvfunc)(struct supernet_info *,struct supernet_endpoint *,int32_t ind,uint8_t *msg,int32_t nnlen);
    queue_t nnrecvQ;
    int32_t nnsock,num; struct endpoint eps[];
};*/

struct category_chain
{
    bits256 *weights,*blocks,category_hwm,cchainhash;
    int32_t hashlen,addrlen,maxblocknum;
    struct supernet_info *myinfo;
    void *categoryinfo,*subinfo;
    int32_t (*blockhash_func)(struct category_chain *cchain,void *blockhashp,void *data,int32_t datalen);
    bits256 (*stake_func)(struct category_chain *cchain,void *addr,int32_t addrlen);
    bits256 (*hit_func)(struct category_chain *cchain,int32_t height,void *prevgenerator,void *addr,void *blockhashp);
    bits256 (*default_func)(struct category_chain *cchain,int32_t func,int32_t height,void *prevgenerator,void *addr,void *blockhashp,bits256 heaviest);
};

struct category_info
{
    UT_hash_handle hh; queue_t Q;
    char *(*processfunc)(struct supernet_info *myinfo,void *data,int32_t datalen,char *remoteaddr);
    struct category_chain *cchain;
    bits256 hash; void *info; struct category_info *sub;
};
extern struct category_info *Categories;
struct category_msg { struct queueitem DL; struct tai t; uint64_t remoteipbits; int32_t len; uint8_t msg[]; };


void expand_epbits(char *endpoint,struct endpoint epbits);
struct endpoint calc_epbits(char *transport,uint32_t ipbits,uint16_t port,int32_t type);

struct supernet_info *SuperNET_MYINFO(char *passphrase);
void SuperNET_init(void *args);
char *SuperNET_JSON(struct supernet_info *myinfo,cJSON *json,char *remoteaddr);

char *SuperNET_jsonstr(struct supernet_info *myinfo,char *jsonstr,char *remoteaddr);
char *SuperNET_DHTencode(struct supernet_info *myinfo,char *destip,bits256 category,bits256 subhash,char *hexmsg,int32_t maxdelay,int32_t broadcastflag,int32_t plaintext);
char *SuperNET_parser(struct supernet_info *myinfo,char *agent,char *method,cJSON *json,char *remoteaddr);
char *SuperNET_processJSON(struct supernet_info *myinfo,cJSON *json,char *remoteaddr);
char *SuperNET_DHTsend(struct supernet_info *myinfo,uint64_t destipbits,bits256 category,bits256 subhash,char *hexmsg,int32_t maxdelay,int32_t broadcastflag,int32_t plaintext);
uint16_t SuperNET_API2num(char *agent,char *method);
int32_t SuperNET_num2API(char *agent,char *method,uint16_t num);
bits256 SuperNET_sharedseed(bits256 privkey,bits256 otherpub);
int32_t SuperNET_decrypt(bits256 *senderpubp,uint64_t *senderbitsp,uint32_t *timestampp,bits256 mypriv,bits256 mypub,uint8_t *dest,int32_t maxlen,uint8_t *src,int32_t len);
cJSON *SuperNET_argjson(cJSON *json);

void *category_info(bits256 categoryhash,bits256 subhash);
void *category_infoset(bits256 categoryhash,bits256 subhash,void *info);
struct category_info *category_find(bits256 categoryhash,bits256 subhash);
void SuperNET_hexmsgprocess(struct supernet_info *myinfo,cJSON *json,char *hexmsg,char *remoteaddr);
struct category_info *category_processfunc(bits256 categoryhash,char *(*process_func)(struct supernet_info *myinfo,void *data,int32_t datalen,char *remoteaddr));
char *pangea_hexmsg(struct supernet_info *myinfo,void *data,int32_t len,char *remoteaddr);
void pangea_queues(struct supernet_info *myinfo);

int32_t SuperNET_str2hex(uint8_t *hex,char *str);
void SuperNET_hex2str(char *str,uint8_t *hex,int32_t len);
void SuperNET_hexmsgadd(struct supernet_info *myinfo,bits256 categoryhash,bits256 subhash,char *hexmsg,struct tai now,char *remoteaddr);
int32_t SuperNET_hexmsgfind(struct supernet_info *myinfo,bits256 category,bits256 subhash,char *hexmsg,int32_t addflag);
void category_posthexmsg(struct supernet_info *myinfo,bits256 categoryhash,bits256 subhash,char *hexmsg,struct tai now,char *remoteaddr);
void *category_subscribe(struct supernet_info *myinfo,bits256 category,bits256 subhash);
struct category_msg *category_gethexmsg(struct supernet_info *myinfo,bits256 categoryhash,bits256 subhash);
char *SuperNET_htmlstr(char *fname,char *htmlstr,int32_t maxsize,char *agentstr);

char *SuperNET_categorymulticast(struct supernet_info *myinfo,int32_t surveyflag,bits256 categoryhash,bits256 subcategory,char *message,int32_t maxdelay,int32_t broadcastflag,int32_t plaintext);
bits256 calc_categoryhashes(bits256 *subhashp,char *category,char *subcategory);
struct category_chain *category_chain_functions(struct supernet_info *myinfo,bits256 categoryhash,bits256 subhash,int32_t hashlen,int32_t addrlen,void *hash_func,void *stake_func,void *hit_func,void *default_func);
#define category_default_latest() (*cchain->default_func)(cchain,'L',0,0,0,0,zero)
void category_init(struct supernet_info *myinfo);
char *SuperNET_keysinit(struct supernet_info *myinfo,char *jsonstr);
double instantdex_aveprice(struct supernet_info *myinfo,char *base,char *rel,double volume,cJSON *argjson);

#endif

