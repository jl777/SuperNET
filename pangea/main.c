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

#ifdef STANDALONE
#define CHROMEAPP_NAME pangea
#define CHROMEAPP_STR "pangea"
#define CHROMEAPP_CONF "pangea.conf"
#define CHROMEAPP_MAIN pangea_main
#define CHROMEAPP_JSON pangea_JSON
#define CHROMEAPP_HANDLER Handler_pangea

#include "../pnacl_main.h"

// ALL globals must be here!

void pangea_main(void *arg)
{
    while ( 1 )
        sleep(777);
}

char *pangea_JSON(char *jsonstr)
{
    return(clonestr("{\"error\":\"pangea is just a stub for now\"}"));
}
#else

char *pangea_parser(struct supernet_info *myinfo,char *method,cJSON *json)
{
    return(clonestr("{\"error\":\"pangea API is not yet\"}"));
}
#endif
