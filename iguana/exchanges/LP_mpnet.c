
/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
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
//
//  LP_mpnet.c
//  marketmaker
//

int32_t LP_tradecommand(void *ctx,char *myipaddr,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen);

void LP_mpnet_send(char *msg)
{
    
}

cJSON *LP_mpnet_get()
{
    return(0);
}

void LP_mpnet_check(void *ctx,char *myipaddr,int32_t pubsock)
{
    while ( (argjson= LP_mpnet_get()) != 0 )
    {
        LP_tradecommand(ctx,myipaddr,pubsock,argjson,0,0);
        free_json(argjson);
    }
}
