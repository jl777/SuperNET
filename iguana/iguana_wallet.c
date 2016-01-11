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

#include "iguana777.h"

struct iguana_waccount *iguana_waccountcreate(struct iguana_info *coin,char *account)
{
    struct iguana_waccount *waddr; int32_t len = (int32_t)strlen(account)+1;
    HASH_FIND(hh,coin->wallet,account,len,waddr);
    if ( waddr != 0 )
        return(waddr);
    waddr = mycalloc('w',1,sizeof(*waddr) + len);
    strcpy(waddr->account,account);
    HASH_ADD(hh,coin->wallet,account,len,waddr);
    return(waddr);
}

struct iguana_waccount *iguana_waccountfind(struct iguana_info *coin,char *account)
{
    struct iguana_waccount *waddr;
    HASH_FIND(hh,coin->wallet,account,strlen(account)+1,waddr);
    return(waddr);
}

struct iguana_waccount *iguana_waccountadd(struct iguana_info *coin,char *walletaccount,struct iguana_waddress *waddr)
{
    struct iguana_waccount *acct;
    if ( (acct= iguana_waccountfind(coin,walletaccount)) == 0 )
        acct = iguana_waccountcreate(coin,walletaccount);
    return(acct);
}

int32_t iguana_waccountswitch(struct iguana_info *coin,struct iguana_waddress *waddr,char *coinaddr)
{
    // what if coinaddr is already in an account?
    //printf("change %s walletaccount.(%s) (%s) <- %s\n",coin->symbol,waddr->account,waddr->coinaddr,coinaddr);
    return(0);
}

struct iguana_waddress *iguana_waddressfind(struct iguana_info *coin,char *coinaddr)
{
    return(0);
}

