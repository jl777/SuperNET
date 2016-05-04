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

/*
 Asset Passport System - first draft spec

 Asset Export - destination blockchain and address, BTC sync
 Asset Import - source blockchain txid or BTCD txid
 
Assets can be exported from any blockchain that supports a burn transaction with an attachment. This attachment needs to have a destination blockchain and address. In case a blockchain cannot support a combined burn with attachment, the burn txid can be added to the export payload and this combined data signed using the source blockchain's signing method to create a BTCD 'APS' OP_RETURN
 
While it is not expected that there will be more than 256 such blockchains, by using the bitcoin varint we can encode an arbitrary number of destination blockchains using one byte, until we need to expand. For now the following one byte codes represent the destination blockchain:
 
 'b' -> bitcoin/BitcoinDark (BTC)
 'c' -> colored coins
 'e' -> ethereum (ETH)
 'n' -> NXT
 'o' -> open assets
 'w' -> WAVES
 'x' -> counterparty (XCP)
 '?' -> please contact jl777 to have asset supporting blockchain added. 
 
 When 0xfc slots are filled, the code (0xfd + 2 bytes) will be used. It is safe to assume there wont be more than 65534 supporting blockchains, but codes 0xfe and 0xff will be reserved just in case
 
 The destination address is the 20 byte rmd160 of the sha256 of the 256 bit privkey, basically the precursor to all bitcoin type of addresses in a coin agnostic format, so this handles all the blockchains that use a bitcoin type of addressing. For blockchains that do not, the method to map its privkeys to a 256 bit privkey needs to be defined. Then the standard rmd160(sha256(mapped privkey)) will be the address
 
By encoding the above 21 bytes into the existing blockchain with the burning of the asset on that blockchain, it no longer exists on the source blockchain and it has a unique destination blockchain.
 
 */
