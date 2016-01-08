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
#include "../includes/nanomsg/nn.h"

#define SUPERNET_PORT 7774
#define SUPERNET_TIMEOUT 10000
#define SUPERNET_MAXPEERS 128

#define LB_OFFSET 1
#define PUBGLOBALS_OFFSET 2
#define PUBRELAYS_OFFSET 3
#define SUPERNET_APIENDPOINT "tcp://127.0.0.1:7776"
#define NXT_TOKEN_LEN 160

#define nn_errstr() nn_strerror(nn_errno())

#define CONNECTION_NUMBITS 10
struct endpoint { uint64_t ipbits:32,port:16,transport:2,nn:4,directind:CONNECTION_NUMBITS; };

#define MAX_SERVERNAME 128
struct relayargs
{
    char name[16],endpoint[MAX_SERVERNAME];
    int32_t sock,type,bindflag,sendtimeout,recvtimeout;
};

struct relay_info { int32_t sock,num,mytype,desttype; struct endpoint connections[1 << CONNECTION_NUMBITS]; };
struct direct_connection { char handler[16]; struct endpoint epbits; int32_t sock; };

struct supernet_info
{
    char ipaddr[64],transport[8]; int32_t APISLEEP; int32_t iamrelay; uint64_t my64bits; uint64_t ipbits;
    int32_t Debuglevel,readyflag,dead;
    int32_t pullsock,subclient,lbclient,lbserver,servicesock,pubglobal,pubrelays,numservers;
    uint16_t port,serviceport,portp2p;
    struct nn_pollfd pfd[16]; struct relay_info active;
};

void expand_epbits(char *endpoint,struct endpoint epbits);
struct endpoint calc_epbits(char *transport,uint32_t ipbits,uint16_t port,int32_t type);

int32_t badass_servers(char servers[][MAX_SERVERNAME],int32_t max,int32_t port);
int32_t crackfoo_servers(char servers[][MAX_SERVERNAME],int32_t max,int32_t port);
void SuperNET_init();

extern int32_t PULLsock;
extern struct relay_info RELAYS;

#endif

