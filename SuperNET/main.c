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

#define CHROMEAPP_NAME SuperNET
#define CHROMEAPP_STR "SuperNET"
#define CHROMEAPP_CONF "SuperNET.conf"
#define CHROMEAPP_MAIN SuperNET_main
#define CHROMEAPP_JSON SuperNET_JSON
#define CHROMEAPP_HANDLER Handler_SuperNET

#include "../pnacl_main.h"

// ALL globals must be here!

void SuperNET_main(void *arg)
{
    while ( 1 )
        sleep(777);
}
