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

#include "iguana777.h"

int32_t category_peer(struct supernet_info *myinfo,struct iguana_peer *addr,bits256 category,bits256 subhash)
{
    return(1);
}

int32_t category_plaintext(struct supernet_info *myinfo,bits256 category,bits256 subhash,int32_t plaintext)
{
    return(plaintext);
}

int32_t category_maxdelay(struct supernet_info *myinfo,bits256 category,bits256 subhash,int32_t maxdelay)
{
    return(maxdelay);
}

int32_t category_broadcast(struct supernet_info *myinfo,bits256 category,bits256 subhash,int32_t broadcastflag)
{
    if ( broadcastflag < 1 )
        broadcastflag = 1;
    else if ( broadcastflag > SUPERNET_MAXHOPS )
        broadcastflag = SUPERNET_MAXHOPS;
    return(broadcastflag);
}

char *SuperNET_categorymulticast(struct supernet_info *myinfo,int32_t surveyflag,bits256 category,bits256 subhash,char *message,int32_t maxdelay,int32_t broadcastflag,int32_t plaintext)
{
    char *hexmsg,*retstr; int32_t len;
    len = (int32_t)strlen(message);
    if ( is_hexstr(message,len) == 0 )
    {
        hexmsg = malloc((len << 1) + 1);
        init_hexbytes_noT(hexmsg,(uint8_t *)message,len+1);
    } else hexmsg = message;
    plaintext = category_plaintext(myinfo,category,subhash,plaintext);
    broadcastflag = category_broadcast(myinfo,category,subhash,broadcastflag);
    maxdelay = category_maxdelay(myinfo,category,subhash,maxdelay);
    retstr = SuperNET_DHTsend(myinfo,0,category,subhash,hexmsg,maxdelay,broadcastflag,plaintext);
    if ( hexmsg != message)
        free(hexmsg);
    return(retstr);
}
