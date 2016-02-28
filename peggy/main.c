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

#define CHROMEAPP_NAME PAX
#define CHROMEAPP_STR "PAX"
#define CHROMEAPP_CONF "PAX.conf"
#define CHROMEAPP_MAIN peggy_main
#define CHROMEAPP_JSON peggy_JSON
#define CHROMEAPP_HANDLER Handler_peggy

#include "../pnacl_main.h"

// ALL globals must be here!

void peggy_main(void *arg)
{
    while ( 1 )
        sleep(777);
}

char *peggy_JSON(char *jsonstr)
{
    return(clonestr("{\"error\":\"peggy is just a stub for now\"}"));
}