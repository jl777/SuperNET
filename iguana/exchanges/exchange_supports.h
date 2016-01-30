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

char *ALLPAIRS(struct exchange_info *exchange,cJSON *argjson)
{
    return(jprint(exchanges777_allpairs(BASERELS,(int32_t)(sizeof(BASERELS)/sizeof(*BASERELS))),1));
}

int32_t SUPPORTS(struct exchange_info *exchange,char *base,char *rel,cJSON *argjson)
{
    return(baserel_polarity(BASERELS,(int32_t)(sizeof(BASERELS)/sizeof(*BASERELS)),base,rel));
}

