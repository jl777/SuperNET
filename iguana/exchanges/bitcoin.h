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

#include "../../includes/openssl/ec.h"
#include "../../includes/openssl/ecdsa.h"
#include "../../includes/openssl/obj_mac.h"

#define SIGHASH_ALL 1
#define SIGHASH_NONE 2
#define SIGHASH_SINGLE 3
#define SIGHASH_ANYONECANPAY 0x80

#define SCRIPT_OP_IF 0x63
#define SCRIPT_OP_ELSE 0x67
#define SCRIPT_OP_DUP 0x76
#define SCRIPT_OP_ENDIF 0x68
#define SCRIPT_OP_TRUE 0x51
#define SCRIPT_OP_2 0x52
#define SCRIPT_OP_3 0x53
#define OP_DROP 0x75
#define SCRIPT_OP_EQUALVERIFY 0x88
#define SCRIPT_OP_HASH160 0xa9
#define SCRIPT_OP_EQUAL 0x87
#define SCRIPT_OP_CHECKSIG 0xac
#define OP_CHECKSEQUENCEVERIFY	0xb2
#define OP_CHECKLOCKTIMEVERIFY 0xb1

struct bp_key { EC_KEY *k; };
