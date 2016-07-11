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

 Asset Export - destination blockchain and address, optional BTC sync
 Asset Import - source blockchain txid/vout or BTCD txid/vout
 
Assets can be exported from any blockchain that supports a burn transaction with an attachment. This attachment needs to have a destination blockchain and address. In case a blockchain cannot support a combined burn with attachment, the burn txid can be added to the export payload and this combined data signed using the source blockchain's signing method to create a BTCD 'APS' OP_RETURN
 
While it is not expected that there will be more than 256 such blockchains, by using the bitcoin varint we can encode an arbitrary number of destination blockchains using one byte, until we need to expand. For now the following one byte codes represent the destination blockchain:
 
 'b' -> bitcoin/BitcoinDark (BTC)
 'c' -> colored coins
 'e' -> ethereum (ETH)
 'h' -> HEAT
 'n' -> NXT
 'o' -> open assets
 's' -> BURST
 'w' -> WAVES
 'x' -> counterparty (XCP)
 '?' -> please contact jl777 to have a new code for asset supporting blockchain added.
 
 When 0xfc slots are filled, the code (0xfd + 2 bytes) will be used. It is safe to assume there wont be more than 65534 supporting blockchains, but codes 0xfe and 0xff will be reserved just in case
 
 The destination address is the 20 byte rmd160 of the sha256 of the 256 bit privkey, basically the precursor to all bitcoin type of addresses in a coin agnostic format, so this handles all the blockchains that use a bitcoin type of addressing. For blockchains that do not, the method to map its privkeys to a 256 bit privkey needs to be defined. Then the standard rmd160(sha256(mapped privkey)) will be the address
 
If many exports from multiple blockchains are done all at the same time, it might be desireable to create an ordering of the exports. To facilitate this, the lower 64-bits of a recent BTC blockhash can be added. Any time sequence resolution will use the height of the first BTC blockhash that matches, scanning backward from the likely starting point based on the source blockchain's timestamp. In order to compensate for clock drift, it is advised to select a BTC block that is 2 blocks in the past. In the event there are multiple exports still tied, the lower 64bits of the txids will be used for a tiebreak. In the event there are still multiple exports tied, then the blockchain code from above will be used. In the event there are multiple exports from the same blockchain that are still tied, then that local blockchain's transaction ordering will be used.
 
By encoding the above 21 (or 28) bytes into the existing blockchain with the burning of the asset on that blockchain, it no longer exists on the source blockchain and it has a unique destination blockchain.
 
Requiring all blockchains to be monitoring all the other blockchains creates an N*N complexity where each blockchain needs to be able to read all the other blockchains. In order to simplify this, the BTCD blockchain can be used to provide a single blockchain that can be accessed via SuperNET API locally or remotely to retrieve a list of asset exports. To facilitate this a BTCD 'APS' OP_RETURN needs to be created by the client software:
    
    OP_RETURN
    'A'
    'P'
    'S'
    <21 or 28 bytes>
    <original blockchain where asset was issued>
    <original assetid>
    <source blockchain byte>
    <source asset amount in satoshis>
    <source blockchain txid of burn> -> contents to be verified against the <21 or 28 bytes>
    <source assetid> -> only needed if original and source blockchain are different
    <signature of the above> -> to be verified with the signer's pubkey of the blockchain txid signer
    <optional BTC txid with SHA256 of above in APS OP_RETURN>

 Asset Import
    Importing assets creates a rather troublesome issue, in that to make it fully automated, all blockchains would need to monitor all the other blockchains for valid Asset Exports and then also to properly issue newly created assets to match. Since some blockchains are not able to issue more assets after the initial issuance, there needs to be a way for a reserve amount of assets to be transfered on demand. However, keeping this reserve totally blockchain controlled could be problematic for some blockchains, so provision for the asset issuer to sign a transfer for valid exports is needed.
 
    Which leads to the following simplification of the process. The asset issuer needs to run a special automated process that monitor's for Asset Exports and when it is received, to send out the appropriate new asset on the destination blockchain. This allows the asset issuer to create appropriate assets on each blockchain and can encapsulate whether new assets are created dynamically, or transferred from a reserve account. When an asset is created for the APS on a blockchain, its specifics should be recorded on the BTCD APS OP_RETURN by the asset issuer:
 
     OP_RETURN
     'A'
     'P'
     'S'
     <original blockchain where asset was issued>
     <original assetid>
     <dest blockchain byte>
     <dest asset issued in satoshis>
     <dest blockchain txid of new issue> 
     <asset name>
     <asset description>
     <signature of the above> -> to be verified with the issuer's pubkey
     <optional BTC txid with SHA256 of above in APS OP_RETURN>

    When the matching Asset Import is completed for an Asset Export, this needs to be recorded with a BTCD APS:
 
     OP_RETURN
     'A'
     'P'
     'S'
     <BTCD APS txid/vout of Asset Export>
     <dest assetid>
     <dest assets transferred in satoshis>
     <dest blockchain txid of transfer>
     <signature of the above> -> to be verified with the issuer's pubkey
     <optional BTC txid with SHA256 of above in APS OP_RETURN>

 
 All of the BTCD APS OP_RETURNS can have security added to them by generating a matched BTC APS OP_RETURN with the SHA256 of the contents of the BTCD APS (including the signature)
 
 In order to simplify signature validation, all signatures will use secp256k1 signatures of the double sha256 hash of the contents.
 
Given the above set of APS OP_RETURNS, the SuperNET passport API will provide aggregate information on the global assets, such as total issued, circulation, assetid mappings, etc
 */
