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
//  statc.c
//
//  Copyright © 2014-2018 SuperNET. All rights reserved.
//

#include <stdio.h>
#include <stdint.h>
#include "../../crypto777/OS_portable.h"

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define STATS_DESTDIR "/var/www/html"

#ifndef _WIN32
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000	// Do not generate SIGPIPE
#endif
#else
#define MSG_NOSIGNAL	0
#endif

#include "DEXstats.h"
extern uint32_t DOCKERFLAG;
extern char LP_myipaddr[];
char ASSETCHAINS_SYMBOL[65] = { "KV" };
uint16_t RPC_port;
char CURRENCIES[][8] = { "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD", // major currencies
                         "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK", // end of currencies
};
