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

/* from https://bitcoin.org/en/developer-reference#rpcs
 Block Chain RPCs
 GetBestBlockHash: returns the header hash of the most recent block on the best block chain. New in 0.9.0
 GetBlock: gets a block with a particular header hash from the local block database either as a JSON object or as a serialized block.
 GetBlockChainInfo: provides information about the current state of the block chain. New in 0.9.2, Updated in 0.10.0
 GetBlockCount: returns the number of blocks in the local best block chain.
 GetBlockHash: returns the header hash of a block at the given height in the local best block chain.
 GetChainTips: returns information about the highest-height block (tip) of each local block chain. New in 0.10.0
 GetDifficulty: returns the proof-of-work difficulty as a multiple of the minimum difficulty.
 GetMemPoolInfo: returns information about the node’s current transaction memory pool. New in 0.10.0
 GetRawMemPool: returns all transaction identifiers (TXIDs) in the memory pool as a JSON array, or detailed information about each transaction in the memory pool as a JSON object.
 GetTxOut: returns details about a transaction output. Only unspent transaction outputs (UTXOs) are guaranteed to be available.
 GetTxOutProof: returns a hex-encoded proof that one or more specified transactions were included in a block. New in 0.11.0
 GetTxOutSetInfo: returns statistics about the confirmed unspent transaction output (UTXO) set. Note that this call may take some time and that it only counts outputs from confirmed transactions—it does not count outputs from the memory pool.
 VerifyChain: verifies each entry in the local block chain database.
 VerifyTxOutProof: verifies that a proof points to one or more transactions in a block, returning the transactions the proof commits to and throwing an RPC error if the block is not in our best block chain. New in 0.11.0
 Control RPCs
 GetInfo: prints various information about the node and the network. Updated in 0.10.0, Deprecated
 Help: lists all available public RPC commands, or gets help for the specified RPC. Commands which are unavailable will not be listed, such as wallet RPCs if wallet support is disabled.
 Stop: safely shuts down the Bitcoin Core server.
 Generating RPCs
 Generate: nearly instantly generates blocks (in regtest mode only) New in master
 GetGenerate: returns true if the node is set to generate blocks using its CPU.
 SetGenerate: enables or disables hashing to attempt to find the next block. Updated in master
 Mining RPCs
 GetBlockTemplate: gets a block template or proposal for use with mining software.
 GetMiningInfo: returns various mining-related information. Updated in master
 GetNetworkHashPS: returns the estimated current or historical network hashes per second based on the last n blocks.
 PrioritiseTransaction: adds virtual priority or fee to a transaction, allowing it to be accepted into blocks mined by this node (or miners which use this node) with a lower priority or fee. (It can also remove virtual priority or fee, requiring the transaction have a higher priority or fee to be accepted into a locally-mined block.) New in 0.10.0
 SubmitBlock: accepts a block, verifies it is a valid addition to the block chain, and broadcasts it to the network. Extra parameters are ignored by Bitcoin Core but may be used by mining pools or other programs.
 Network RPCs
 AddNode: attempts to add or remove a node from the addnode list, or to try a connection to a node once.
 GetAddedNodeInfo: returns information about the given added node, or all added nodes (except onetry nodes). Only nodes which have been manually added using the addnode RPC will have their information displayed.
 GetConnectionCount: returns the number of connections to other nodes.
 GetNetTotals: returns information about network traffic, including bytes in, bytes out, and the current time.
 GetNetworkInfo: returns information about the node’s connection to the network. New in 0.9.2, Updated in 0.10.0
 GetPeerInfo: returns data about each connected network node. Updated in 0.10.0
 Ping: sends a P2P ping message to all connected nodes to measure ping time. Results are provided by the getpeerinfo RPC pingtime and pingwait fields as decimal seconds. The P2P ping message is handled in a queue with all other commands, so it measures processing backlog, not just network ping.
 Raw Transaction RPCs
 CreateRawTransaction: creates an unsigned serialized transaction that spends a previous output to a new output with a P2PKH or P2SH address. The transaction is not stored in the wallet or transmitted to the network.
 DecodeRawTransaction: decodes a serialized transaction hex string into a JSON object describing the transaction.
 DecodeScript: decodes a hex-encoded P2SH redeem script.
 GetRawTransaction: gets a hex-encoded serialized transaction or a JSON object describing the transaction. By default, Bitcoin Core only stores complete transaction data for UTXOs and your own transactions, so the RPC may fail on historic transactions unless you use the non-default txindex=1 in your Bitcoin Core startup settings.
 SendRawTransaction: validates a transaction and broadcasts it to the peer-to-peer network.
 SignRawTransaction: signs a transaction in the serialized transaction format using private keys stored in the wallet or provided in the call.
 Utility RPCs
 CreateMultiSig: creates a P2SH multi-signature address.
 EstimateFee: estimates the transaction fee per kilobyte that needs to be paid for a transaction to be included within a certain number of blocks. New in 0.10.0
 EstimatePriority: estimates the priority that a transaction needs in order to be included within a certain number of blocks as a free high-priority transaction. New in 0.10.0
 ValidateAddress: returns information about the given Bitcoin address.
 VerifyMessage: verifies a signed message.
 Wallet RPCs
 Note: the wallet RPCs are only available if Bitcoin Core was built with wallet support, which is the default.
 
 AddMultiSigAddress: adds a P2SH multisig address to the wallet.
 BackupWallet: safely copies wallet.dat to the specified file, which can be a directory or a path with filename.
 DumpPrivKey: returns the wallet-import-format (WIP) private key corresponding to an address. (But does not remove it from the wallet.)
 DumpWallet: creates or overwrites a file with all wallet keys in a human-readable format.
 EncryptWallet: encrypts the wallet with a passphrase. This is only to enable encryption for the first time. After encryption is enabled, you will need to enter the passphrase to use private keys.
 GetAccountAddress: returns the current Bitcoin address for receiving payments to this account. If the account doesn’t exist, it creates both the account and a new address for receiving payment. Once a payment has been received to an address, future calls to this RPC for the same account will return a different address.
 GetAccount: returns the name of the account associated with the given address.
 GetAddressesByAccount: returns a list of every address assigned to a particular account.
 GetBalance: gets the balance in decimal bitcoins across all accounts or for a particular account.
 GetNewAddress: returns a new Bitcoin address for receiving payments. If an account is specified, payments received with the address will be credited to that account.
 GetRawChangeAddress: returns a new Bitcoin address for receiving change. This is for use with raw transactions, not normal use.
 GetReceivedByAccount: returns the total amount received by addresses in a particular account from transactions with the specified number of confirmations. It does not count coinbase transactions.
 GetReceivedByAddress: returns the total amount received by the specified address in transactions with the specified number of confirmations. It does not count coinbase transactions.
 GetTransaction: gets detailed information about an in-wallet transaction. Updated in 0.10.0
 GetUnconfirmedBalance: returns the wallet’s total unconfirmed balance.
 GetWalletInfo: provides information about the wallet. New in 0.9.2
 ImportAddress: adds an address or pubkey script to the wallet without the associated private key, allowing you to watch for transactions affecting that address or pubkey script without being able to spend any of its outputs. New in 0.10.0
 ImportPrivKey: adds a private key to your wallet. The key should be formatted in the wallet import format created by the dumpprivkey RPC.
 ImportWallet: imports private keys from a file in wallet dump file format (see the dumpwallet RPC). These keys will be added to the keys currently in the wallet. This call may need to rescan all or parts of the block chain for transactions affecting the newly-added keys, which may take several minutes.
 KeyPoolRefill: fills the cache of unused pre-generated keys (the keypool).
 ListAccounts: lists accounts and their balances. Updated in 0.10.0
 ListAddressGroupings: lists groups of addresses that may have had their common ownership made public by common use as inputs in the same transaction or from being used as change from a previous transaction.
 ListLockUnspent: returns a list of temporarily unspendable (locked) outputs.
 ListReceivedByAccount: lists the total number of bitcoins received by each account. Updated in 0.10.0
 ListReceivedByAddress: lists the total number of bitcoins received by each address. Updated in 0.10.0
 ListSinceBlock: gets all transactions affecting the wallet which have occurred since a particular block, plus the header hash of a block at a particular depth. Updated in 0.10.0
 ListTransactions: returns the most recent transactions that affect the wallet. Updated in 0.10.0
 ListUnspent: returns an array of unspent transaction outputs belonging to this wallet. Updated in 0.10.0
 LockUnspent: temporarily locks or unlocks specified transaction outputs. A locked transaction output will not be chosen by automatic coin selection when spending bitcoins. Locks are stored in memory only, so nodes start with zero locked outputs and the locked output list is always cleared when a node stops or fails.
 Move: moves a specified amount from one account in your wallet to another using an off-block-chain transaction.
 SendFrom: spends an amount from a local account to a bitcoin address.
 SendMany: creates and broadcasts a transaction which sends outputs to multiple addresses.
 SendToAddress: spends an amount to a given address.
 SetAccount: puts the specified address in the given account.
 SetTxFee: sets the transaction fee per kilobyte paid by transactions created by this wallet.
 SignMessage: signs a message with the private key of an address.
 WalletLock: removes the wallet encryption key from memory, locking the wallet. After calling this method, you will need to call walletpassphrase again before being able to call any methods which require the wallet to be unlocked.
 WalletPassphrase: stores the wallet decryption key in memory for the indicated number of seconds. Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock time that overrides the old one.
 WalletPassphraseChange: changes the wallet passphrase from ‘old passphrase’ to ‘new passphrase’.
 Removed RPCs
 GetHashesPerSec: was removed in Bitcoin Core master (unreleased). It returned a recent hashes per second performance measurement when the node was generating blocks.
 GetWork: was removed in Bitcoin Core 0.10.0.
 RPCs
 Warning icon Warning: the block chain and memory pool can include arbitrary data which several of the commands below will return in hex format. If you convert this data to another format in an executable context, it could be used in an exploit. For example, displaying a pubkey script as ASCII text in a webpage could add arbitrary Javascript to that page and create a cross-site scripting (XSS) exploit. To avoid problems, please treat block chain and memory pool data as an arbitrary input from an untrusted source.
 
 */

ZERO_ARGS(getinfo);
ZERO_ARGS(getbestblockhash);
ZERO_ARGS(getblockcount);
ZERO_ARGS(listaddressgroupings);
ZERO_ARGS(walletlock);
ZERO_ARGS(checkwallet);
ZERO_ARGS(repairwallet);
ZERO_ARGS(makekeypair);
ZERO_ARGS(gettxoutsetinfo);
ZERO_ARGS(listlockunspent);
ZERO_ARGS(getrawchangeaddress);

TWO_INTS(listaccounts,minconf,includewatchonly);
TWO_INTS(listreceivedbyaddress,minconf,includeempty);
TWOINTS_AND_ARRAY(listunspent,minconf,maxconf,array);

STRING_ARG(dumpwallet,filename);
STRING_ARG(backupwallet,filename);
STRING_ARG(encryptwallet,passphrase);
STRING_ARG(validatepubkey,pubkey);
STRING_ARG(getnewaddress,account);
STRING_ARG(vanitygen,vanity);

STRING_ARG(getaddressesbyaccount,account);
STRING_ARG(getaccount,address);
STRING_ARG(getaccountaddress,account);
STRING_ARG(dumpprivkey,address);
STRING_ARG(importwallet,filename);
STRING_ARG(decoderawtransaction,rawtx);
STRING_ARG(decodescript,script);

TWO_STRINGS(setaccount,address,account);
TWO_STRINGS(walletpassphrasechange,oldpassphrase,newpassphrase);
TWO_STRINGS(signmessage,address,message);

THREE_STRINGS(verifymessage,address,sig,message);
THREE_INTS(listreceivedbyaccount,confirmations,includeempty,watchonly);
THREE_INTS(getbalance,confirmations,includeempty,watchonly);

TWOSTRINGS_AND_INT(importprivkey,wif,account,rescan);
STRING_AND_INT(getreceivedbyaccount,account,includeempty);
STRING_AND_INT(walletpassphrase,passphrase,timeout);
STRING_AND_INT(getreceivedbyaddress,address,minconf);
STRING_AND_INT(sendrawtransaction,rawtx,allowhighfees);

HASH_AND_INT(listsinceblock,blockhash,target);
HASH_AND_INT(getrawtransaction,txid,verbose);

STRING_AND_THREEINTS(listtransactions,account,count,skip,includewatchonly);

HASH_AND_TWOINTS(gettxout,txid,vout,mempool);

DOUBLE_ARG(settxfee,amount);

INT_AND_ARRAY(lockunspent,flag,array);
INT_ARRAY_STRING(createmultisig,M,array,account);

TWO_ARRAYS(createrawtransaction,vins,vouts);
STRING_AND_TWOARRAYS(signrawtransaction,rawtx,vins,privkeys);

SS_D_I_S(move,fromaccount,toaccount,amount,minconf,comment);
SS_D_I_SS(sendfrom,fromaccount,toaddress,amount,minconf,comment,comment2);
S_A_I_S(sendmany,fromaccount,array,minconf,comment);
S_D_SS(sendtoaddress,address,amount,comment,comment2);
