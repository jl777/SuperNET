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

#ifndef H_DATACHAIN_H
#define H_DATACHAIN_H

// Mutually Exclusive - first one to get this value is the only one that can get it, subsequent requests get rejected, unless it is from the original creator of the specific data item

// Majority (threshold) vote - anybody can submit, but until the required thresholds are met there is no valid value

// Auction and reverse auction - anybody can submit, everybody sees the highest (lowest) value

// Random - value is a random value, but all nodes get the same value, useful for lottery type of use cases

// MofN - shamir's shared secret

// Pegged - values can be derived from external data feeds and pegged to a moving average

// Averaged - value is a determistically chosen value that is close to the majority of other values in the time period. it is not a true mathematical average, but over time will be very close to the average. The advantage is that submission of bogus values wont affect things much.

// Orderbook - price and volume are combined for bids and asks, Orderbook is constructed from auction (bid) and reverse auction (ask)

// Oneshot (limited triggers) - defined value can only happen the specified number of times, then the data field is expired

// Derived - value is derived from a combination of other values using a standard set of operations. For binary evaluation, values above 0 are treated as true, below zero as false and 0 means undefined. If any value a derived field depends on is undefined, then it also is undefined.

// Scripts - turing complete scripts can be specified in C, that will have access to all the data fields and be able to do standard transactions and invoke any of the other derived data types.

#define DATACHAIN_TYPE_BALANCE 1
#define DATACHAIN_TYPE_DEPOSIT 2
#define DATACHAIN_TYPE_PAYMENT 3
#define DATACHAIN_TYPE_GROUP 4
#define DATACHAIN_TYPE_QUOTE 5

#define DATACHAIN_TYPE_EXCLUSIVE 10
#define DATACHAIN_TYPE_MAJORITY 11
#define DATACHAIN_TYPE_AUCTION 12
#define DATACHAIN_TYPE_REVAUCTION 13

#define DATACHAIN_TYPE_RANDOM 20
#define DATACHAIN_TYPE_MOFN 21
#define DATACHAIN_TYPE_PEGGED 22

#define DATACHAIN_TYPE_AVERAGED 100
#define DATACHAIN_TYPE_ORDERBOOK 101
#define DATACHAIN_TYPE_DERIVED 102

#define DATACHAIN_TYPE_TRIGGER 200

#define DATACHAIN_TYPE_TURING 1000
#define DATACHAIN_TYPE_GATEWAY 1001

#define DATACHAIN_ACTION_SWAP 10000
#define DATACHAIN_ACTION_PAY 10001
#define DATACHAIN_ACTION_BID 10002
#define DATACHAIN_ACTION_ASK 10003
#define DATACHAIN_ACTION_QUOTE 10004
#define DATACHAIN_ACTION_SENDGROUP 10005

struct datachain_itemexclusive { uint8_t ownerpub[33]; };

struct datachain_item
{
    struct iguana_info *coin;
    uint64_t value;
    int32_t firstheight;
    uint32_t expiration; // expires first time BTCD block timestamp exceeds expiration
    uint16_t type,scaling,minconfirms;
    char label[32];
    uint8_t rmd160[20];
    uint8_t itemdata[];
};

struct datachain_info
{
};


#endif
