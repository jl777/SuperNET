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

int32_t SuperNET_hexmsgfind(struct supernet_info *myinfo,bits256 dest,char *hexmsg,int32_t addflag)
{
    static int lastpurge; static uint64_t Packetcache[1024];
    bits256 packethash; int32_t i,datalen;
    datalen = (int32_t)strlen(hexmsg) + 1;
    vcalc_sha256(0,packethash.bytes,(void *)hexmsg,datalen);
    if ( bits256_nonz(dest) == 0 )
        dest = GENESIS_PUBKEY;
    packethash = curve25519(dest,packethash);
    printf("addflag.%d packethash.%llx dest.%llx\n",addflag,(long long)packethash.txid,(long long)dest.txid);
    for (i=0; i<sizeof(Packetcache)/sizeof(*Packetcache); i++)
    {
        if ( Packetcache[i] == 0 )
        {
            if ( addflag != 0 )
            {
                Packetcache[i] = packethash.txid;
                //printf("add.%llx packetcache(%s) -> slot[%d]\n",(long long)packethash.txid,hexmsg,i);
            }
            break;
        }
        else if ( Packetcache[i] == packethash.txid )
        {
            printf("SuperNET_DHTsend reject duplicate packet.%llx (%s)\n",(long long)packethash.txid,hexmsg);
            return(i);
        }
    }
    if ( i == sizeof(Packetcache)/sizeof(*Packetcache) )
    {
        if ( addflag != 0 )
        {
            printf("purge slot[%d]\n",lastpurge);
            Packetcache[lastpurge++] = packethash.txid;
            if ( lastpurge >= sizeof(Packetcache)/sizeof(*Packetcache) )
                lastpurge = 0;
        }
    }
    return(-1);
}

void SuperNET_hexmsgadd(struct supernet_info *myinfo,bits256 destpub,char *hexmsg,struct tai now)
{
    char str[65];
    if ( memcmp(destpub.bytes,GENESIS_PUBKEY.bytes,sizeof(destpub)) == 0 )
        strcpy(str,"BROADCAST");
    else bits256_str(str,destpub);
    printf("HEXMSG.(%s) -> %s\n",hexmsg,str);
}
