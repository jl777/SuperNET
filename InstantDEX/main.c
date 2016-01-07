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

#define CHROMEAPP_NAME InstantDEX
#define CHROMEAPP_STR "InstantDEX"
#define CHROMEAPP_CONF "InstantDEX.conf"
#define CHROMEAPP_MAIN InstantDEX_main
#define CHROMEAPP_JSON InstantDEX_JSON
#define CHROMEAPP_HANDLER Handler_InstantDEX

#include "../pnacl_main.h"

// ALL globals must be here!

void InstantDEX_main(void *arg)
{
    while ( 1 )
        sleep(777);
}

char *InstantDEX_JSON(char *jsonstr)
{
    return(clonestr("{\"error\":\"InstantDEX is just a stub for now\"}"));
}