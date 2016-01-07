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

#include "iguana777.h"
#define PUBKEY_ADDRESS_BTC 0
#define SCRIPT_ADDRESS_BTC 5
#define PRIVKEY_ADDRESS_BTC 128
#define PUBKEY_ADDRESS_BTCD 60
#define SCRIPT_ADDRESS_BTCD 85
#define PRIVKEY_ADDRESS_BTCD 188
#define PUBKEY_ADDRESS_TEST 111
#define SCRIPT_ADDRESS_TEST 196
#define PRIVKEY_ADDRESS_TEST 239

static struct iguana_chain Chains[] =
{
	[CHAIN_TESTNET3] =
    {
		//CHAIN_TESTNET3,
        "testnet3", "tBTC",
		PUBKEY_ADDRESS_TEST, SCRIPT_ADDRESS_TEST, PRIVKEY_ADDRESS_TEST,
		"\x0b\x11\x09\x07",
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
        18333,18334,0,
    },
    [CHAIN_BITCOIN] =
    {
		//CHAIN_BITCOIN,
        "bitcoin", "BTC",
		0, 5, 0x80,
		"\xf9\xbe\xb4\xd9",
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
        8333,8334,0,
        { { 210000, (50 * SATOSHIDEN) }, { 420000, (50 * SATOSHIDEN) / 2 }, { 630000, (50 * SATOSHIDEN) / 4 },{ 840000, (50 * SATOSHIDEN) / 8 },
        }
	},
	[CHAIN_BTCD] =
    {
		//CHAIN_BTCD,
        "btcd", "BTCD",
		PUBKEY_ADDRESS_BTCD, SCRIPT_ADDRESS_BTCD, PRIVKEY_ADDRESS_BTCD,
		"\xe4\xc2\xd8\xe6",
        "0000044966f40703b516c5af180582d53f783bfd319bb045e2dc3e05ea695d46",
        "0100000000000000000000000000000000000000000000000000000000000000000000002b5b9d8cdd624d25ce670a7aa34726858388da010d4ca9ec8fd86369cc5117fd0132a253ffff0f1ec58c7f0001010000000132a253010000000000000000000000000000000000000000000000000000000000000000ffffffff4100012a3d3138204a756e652032303134202d204269746f696e20796f75722077617920746f206120646f75626c6520657370726573736f202d20636e6e2e636f6dffffffff010000000000000000000000000000",
        14631,14632,1,
    },
};

void iguana_chaininit(struct iguana_chain *chain,int32_t hasheaders)
{
    chain->hasheaders = hasheaders;
    if ( strcmp(chain->symbol,"bitcoin") == 0 )
    {
        chain->unitval = 0x1d;
    }
    else
    {
        if ( chain->unitval == 0 )
            chain->unitval = 0x1e;
    }
    if ( hasheaders != 0 )
    {
        strcpy(chain->gethdrsmsg,"getheaders");
        chain->bundlesize = _IGUANA_HDRSCOUNT;
    }
    else
    {
        strcpy(chain->gethdrsmsg,"getblocks");
        chain->bundlesize = _IGUANA_BLOCKHASHES;
    }
    decode_hex((uint8_t *)chain->genesis_hashdata,32,(char *)chain->genesis_hash);
    if ( chain->ramchainport == 0 )
        chain->ramchainport = chain->portp2p - 1;
    if ( chain->portrpc == 0 )
        chain->portrpc = chain->portp2p + 1;
}

struct iguana_chain *iguana_chainfind(char *name)
{
    struct iguana_chain *chain; uint32_t i;
	for (i=0; i<sizeof(Chains)/sizeof(*Chains); i++)
    {
		chain = &Chains[i];
        printf("chain.(%s).%s vs %s.%d\n",chain->genesis_hash,chain->name,name,strcmp(name,chain->name));
		if ( chain->name[0] == 0 || chain->genesis_hash == 0 )
			continue;
		if ( strcmp(name,chain->symbol) == 0 )
        {
            iguana_chaininit(chain,strcmp(chain->symbol,"BTC") == 0);
            return(chain);
        }
	}
	return NULL;
}

struct iguana_chain *iguana_findmagic(uint8_t netmagic[4])
{
    struct iguana_chain *chain; uint8_t i;
	for (i=0; i<sizeof(Chains)/sizeof(*Chains); i++)
    {
		chain = &Chains[i];
		if ( chain->name[0] == 0 || chain->genesis_hash == 0 )
			continue;
		if ( memcmp(netmagic,chain->netmagic,4) == 0 )
			return(iguana_chainfind((char *)chain->symbol));
	}
	return NULL;
}

uint64_t iguana_miningreward(struct iguana_info *coin,uint32_t blocknum)
{
    int32_t i; uint64_t reward = 50LL * SATOSHIDEN;
    for (i=0; i<sizeof(coin->chain->rewards)/sizeof(*coin->chain->rewards); i++)
    {
        //printf("%d: %u %.8f\n",i,(int32_t)coin->chain->rewards[i][0],dstr(coin->chain->rewards[i][1]));
        if ( blocknum >= coin->chain->rewards[i][0] )
            reward = coin->chain->rewards[i][1];
        else break;
    }
    return(reward);
}

struct iguana_chain *iguana_createchain(cJSON *json)
{
    char *symbol,*name,*hexstr; cJSON *rewards,*rpair,*item; int32_t i,m,n; struct iguana_chain *chain = 0;
    if ( (symbol= jstr(json,"name")) != 0 && strlen(symbol) < 8 )
    {
        chain = mycalloc('C',1,sizeof(*chain));
        strcpy(chain->symbol,symbol);
        if ( (name= jstr(json,"description")) != 0 && strlen(name) < 32 )
            strcpy(chain->name,name);
        if ( (hexstr= jstr(json,"pubval")) != 0 && strlen(hexstr) == 2 )
            decode_hex((uint8_t *)&chain->pubval,1,hexstr);
        if ( (hexstr= jstr(json,"scriptval")) != 0 && strlen(hexstr) == 2 )
            decode_hex((uint8_t *)&chain->p2shval,1,hexstr);
        if ( (hexstr= jstr(json,"wipval")) != 0 && strlen(hexstr) == 2 )
            decode_hex((uint8_t *)&chain->wipval,1,hexstr);
        if ( (hexstr= jstr(json,"netmagic")) != 0 && strlen(hexstr) == 8 )
            decode_hex((uint8_t *)chain->netmagic,1,hexstr);
        if ( (hexstr= jstr(json,"unitval")) != 0 && strlen(hexstr) == 2 )
            decode_hex((uint8_t *)&chain->unitval,1,hexstr);
        if ( (hexstr= jstr(json,"genesishash")) != 0 )
        {
            chain->genesis_hash = mycalloc('G',1,strlen(hexstr)+1);
            strcpy(chain->genesis_hash,hexstr);
        }
        if ( (hexstr= jstr(json,"genesisblock")) != 0 )
        {
            chain->genesis_hex = mycalloc('G',1,strlen(hexstr)+1);
            strcpy(chain->genesis_hex,hexstr);
        }
        chain->portp2p = juint(json,"p2p");
        if ( (chain->ramchainport= juint(json,"ramchain")) == 0 )
            chain->ramchainport = chain->portp2p - 1;
        if ( (chain->portrpc= juint(json,"rpc")) == 0 )
            chain->portrpc = chain->portp2p + 1;
        chain->hastimestamp = juint(json,"hastimestamp");
        if ( (rewards= jarray(&n,json,"rewards")) != 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(rewards,i);
                if ( (rpair= jarray(&m,item,0)) != 0 && m == 0 )
                {
                    chain->rewards[i][0] = j64bits(jitem(rpair,0),0);
                    chain->rewards[i][1] = j64bits(jitem(rpair,1),0);
                }
            }
        }
        iguana_chaininit(chain,juint(json,"hasheaders"));
    }
    return(chain);
}
