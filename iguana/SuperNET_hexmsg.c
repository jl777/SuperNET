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

int32_t SuperNET_hexmsgfind(struct supernet_info *myinfo,bits256 category,bits256 subhash,char *hexmsg,int32_t addflag)
{
    static int lastpurge; static uint64_t Packetcache[1024];
    bits256 packethash; int32_t i,datalen;
    datalen = (int32_t)strlen(hexmsg) + 1;
    vcalc_sha256(0,packethash.bytes,(void *)hexmsg,datalen);
    if ( bits256_nonz(category) == 0 )
        category = GENESIS_PUBKEY;
    if ( bits256_nonz(subhash) == 0 )
        subhash = GENESIS_PUBKEY;
    packethash = curve25519(category,packethash);
    //printf("addflag.%d packethash.%llx dest.%llx\n",addflag,(long long)packethash.txid,(long long)category.txid);
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
            printf("SuperNET_DHTsend reject duplicate packet.%llx\n",(long long)packethash.txid);
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

void SuperNET_hexmsgadd(struct supernet_info *myinfo,bits256 categoryhash,bits256 subhash,char *hexmsg,struct tai now)
{
    char str[512],str2[65];
    str[0] = 0;
    if ( memcmp(categoryhash.bytes,GENESIS_PUBKEY.bytes,sizeof(categoryhash)) == 0 )
        strcpy(str,"BROADCAST.");
    else bits256_str(str+strlen(str),category);
    if ( memcmp(subhash.bytes,GENESIS_PUBKEY.bytes,sizeof(subhash)) != 0 )
    {
        bits256_str(str2,subhash);
        strcat(str,str2);
    }
    category_posthexmsg(myinfo,categoryhash,subhash,hexmsg,now);
    printf("HEXMSG.(%s).%llx -> %s\n",hexmsg,(long long)subhash.txid,str);
}
