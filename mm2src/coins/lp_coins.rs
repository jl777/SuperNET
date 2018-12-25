
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
//  coins.rs
//  marketmaker
//

#[macro_use] extern crate common;
#[macro_use] extern crate fomat_macros;
#[macro_use] extern crate futures;
#[macro_use] extern crate gstuff;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate unwrap;

use common::{bitcoin_ctx, bits256, lp};
use common::mm_ctx::{from_ctx, MmArc};
use futures::{Future};
use gstuff::now_ms;
use hashbrown::hash_map::{HashMap, RawEntryMut};
use libc::{c_char, c_void};
use serde_json::{Value as Json};
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::mem::zeroed;
use std::ops::Deref;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

#[doc(hidden)]
pub mod coins_tests;
pub mod eth;
pub mod utxo;
use self::utxo::{coin_from_iguana_info, ExtendedUtxoTx, UtxoCoin};

pub trait Transaction: Debug + 'static {
    fn to_raw_bytes(&self) -> Vec<u8>;
    fn extract_secret(&self) -> Result<Vec<u8>, String>;
}

#[derive(Clone)]
pub enum TransactionEnum {
    ExtendedUtxoTx (ExtendedUtxoTx)
}

impl From<ExtendedUtxoTx> for TransactionEnum {
    fn from (t: ExtendedUtxoTx) -> TransactionEnum {
        TransactionEnum::ExtendedUtxoTx (t)
}   }

// NB: When stable and groked by IDEs, `enum_dispatch` can be used instead of `Deref` to speed things up.
impl Deref for TransactionEnum {
    type Target = Transaction;
    fn deref (&self) -> &dyn Transaction {
        match self {
            &TransactionEnum::ExtendedUtxoTx (ref t) => t
}   }   }

pub type TransactionFut = Box<dyn Future<Item=TransactionEnum, Error=String>>;

/// Operations that coins have independenty from the MarketMaker.
/// That is, things implemented by the coin wallets or public coin services.
pub trait MarketCoinOps: Debug + 'static {
    fn address(&self) -> Cow<str>;

    fn send_buyer_fee(&self, fee_addr: &[u8], amount: f64) -> TransactionFut;

    fn send_buyer_payment(
        &self,
        time_lock: u32,
        pub_a0: &[u8],
        pub_b0: &[u8],
        priv_bn_hash: &[u8],
        amount: f64,
    ) -> TransactionFut;

    fn send_seller_payment(
        &self,
        time_lock: u32,
        pub_a0: &[u8],
        pub_b0: &[u8],
        priv_bn_hash: &[u8],
        amount: f64
    ) -> TransactionFut;

    fn send_seller_spends_buyer_payment(
        &self,
        buyer_payment_tx: TransactionEnum,
        b_priv_0: &[u8],
        b_priv_n: &[u8],
        amount: f64
    ) -> TransactionFut;

    fn send_buyer_spends_seller_payment(
        &self,
        seller_payment_tx: TransactionEnum,
        a_priv_0: &[u8],
        b_priv_n: &[u8],
        amount: f64
    ) -> TransactionFut;

    fn send_buyer_refunds_payment(
        &self,
        buyer_payment_tx: TransactionEnum,
        a_priv_0: &[u8],
        amount: f64
    ) -> TransactionFut;

    fn send_seller_refunds_payment(
        &self,
        seller_payment_tx: TransactionEnum,
        b_priv_0: &[u8],
        amount: f64
    ) -> TransactionFut;

    fn get_balance(&self) -> f64;

    fn send_raw_tx(&self, tx: TransactionEnum) -> TransactionFut;

    fn wait_for_confirmations(
        &self,
        tx: TransactionEnum,
        confirmations: i32,
    ) -> Box<dyn Future<Item=(), Error=String>>;

    fn wait_for_tx_spend(&self, transaction: TransactionEnum, wait_until: u64) -> TransactionFut;

    fn tx_from_raw_bytes(&self, bytes: &[u8]) -> Result<TransactionEnum, String>;
}

/// Common functions that every coin must implement to be exchanged on MM
/// Amounts are f64, it's responsibility of particular implementation to convert it to
/// integer amount depending on decimals.
/// 
/// NB: Implementations are expected to follow the pImpl idiom, providing cheap reference-counted cloning and garbage collection.
pub trait MmCoin: MarketCoinOps {
    // `MmCoin` is an extension fulcrum for something that doesn't fit the `MarketCoinOps`. Practical examples:
    // name (might be required for some APIs, CoinMarketCap for instance);
    // enabled (a piece of MM-specific configuration);
    // coin statistics that we might want to share with UI;
    // state serialization, to get full rewind and debugging information about the coins participating in a SWAP operation.
}

#[derive(Clone, Debug)]
pub enum MmCoinEnum {
    UtxoCoin (UtxoCoin)
}

impl From<UtxoCoin> for MmCoinEnum {
    fn from (c: UtxoCoin) -> MmCoinEnum {
        MmCoinEnum::UtxoCoin (c)
}   }

// NB: When stable and groked by IDEs, `enum_dispatch` can be used instead of `Deref` to speed things up.
impl Deref for MmCoinEnum {
    type Target = MmCoin;
    fn deref (&self) -> &dyn MmCoin {
        match self {
            &MmCoinEnum::UtxoCoin (ref c) => c
}   }   }

struct CoinsContext {
    /// A map from a currencty ticker symbol to the corresponding coin.  
    /// Similar to `LP_coins`.
    coins: Mutex<HashMap<String, MmCoinEnum>>
}
impl CoinsContext {
    /// Obtains a reference to this crate context, creating it if necessary.
    fn from_ctx (ctx: &MmArc) -> Result<Arc<CoinsContext>, String> {
        Ok (try_s! (from_ctx (&ctx.coins_ctx, move || {
            Ok (CoinsContext {
                coins: Mutex::new (HashMap::new())
            })
        })))
    }
}

/*
char *portstrs[][3] = { { "BTC", "8332" }, { "KMD", "7771" } };

int32_t LP_is_slowcoin(char *symbol)
{
    if ( strcmp(symbol,"BTC") == 0 )
        return(2);
    else if ( strcmp(symbol,"BCH") == 0 )
        return(1);
    else if ( strcmp(symbol,"BTG") == 0 )
        return(1);
    else if ( strcmp(symbol,"SBTC") == 0 )
        return(1);
    else return(0);
}

uint16_t LP_rpcport(char *symbol)
{
    int32_t i;
    if ( symbol != 0 && symbol[0] != 0 )
    {
        for (i=0; i<sizeof(portstrs)/sizeof(*portstrs); i++)
            if ( strcmp(portstrs[i][0],symbol) == 0 )
                return(atoi(portstrs[i][1]));
    }
    return(0);
}

uint16_t LP_busport(uint16_t rpcport)
{
    if ( rpcport == 8332 )
        return(8334); // BTC
    else if ( rpcport < (1 << 15) )
        return(65535 - rpcport);
    else return(rpcport+1);
}

char *parse_conf_line(char *line,char *field)
{
    line += strlen(field);
    for (; *line!='='&&*line!=0; line++)
        break;
    if ( *line == 0 )
        return(0);
    if ( *line == '=' )
        line++;
    while ( line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n' || line[strlen(line)-1] == ' ' )
        line[strlen(line)-1] = 0;
    //printf("LINE.(%s)\n",line);
    _stripwhite(line,0);
    return(clonestr(line));
}

uint16_t LP_userpassfp(char *symbol,char *username,char *password,FILE *fp)
{
    char *rpcuser,*rpcpassword,*str,line[8192]; uint16_t port = 0;
    rpcuser = rpcpassword = 0;
    username[0] = password[0] = 0;
    while ( fgets(line,sizeof(line),fp) != 0 )
    {
        if ( line[0] == '#' )
            continue;
        //printf("line.(%s) %p %p\n",line,strstr(line,(char *)"rpcuser"),strstr(line,(char *)"rpcpassword"));
        if ( (str= strstr(line,(char *)"rpcuser")) != 0 )
            rpcuser = parse_conf_line(str,(char *)"rpcuser");
        else if ( (str= strstr(line,(char *)"rpcpassword")) != 0 )
            rpcpassword = parse_conf_line(str,(char *)"rpcpassword");
        else if ( (str= strstr(line,(char *)"rpcport")) != 0 )
        {
            str = parse_conf_line(str,(char *)"rpcport");
            if ( str != 0 )
            {
                port = atoi(str);
                printf("found RPCPORT.%u\n",port);
                free(str);
            }
        }
    }
    if ( rpcuser != 0 && rpcpassword != 0 )
    {
        strcpy(username,rpcuser);
        strcpy(password,rpcpassword);
    }
    //printf("%s rpcuser.(%s) rpcpassword.(%s)\n",symbol,rpcuser,rpcpassword);
    if ( rpcuser != 0 )
        free(rpcuser);
    if ( rpcpassword != 0 )
        free(rpcpassword);
    return(port);
}

void LP_statefname(char *fname,char *symbol,char *assetname,char *str,char *name,char *confpath)
{
    if ( confpath != 0 && confpath[0] != 0 )
    {
		#if defined(NATIVE_WINDOWS)
		// need to do something with "confpath":"`${process.env.HOME}`/.muecore/mue.conf" under Windows
		char *ht = "`${process.env.USERHOME}`", *ht_start, *p_ht;
		char ht_symbol[2];
		
		ht_start = strstr(confpath, ht);

		if (ht_start) {
			ht_start = ht_start + strlen(ht);
			sprintf(fname, "%s\\", LP_getdatadir());
			p_ht = ht_start;
			if (p_ht[0] == '/' && p_ht[1] == '.') {
				p_ht += 2;
				//printf("%s\n", p_ht);
				while (p_ht[0] != '\0') {
					if (p_ht[0] == '/') strcat(fname, "\\"); else
					{
						ht_symbol[0] = p_ht[0]; ht_symbol[1] = '\0';
						strcat(fname, ht_symbol);
					}
					p_ht++;
				}
				//printf("%s\n", fname);
			}
		} else strcpy(fname, confpath);
		#else
		strcpy(fname,confpath);
		#endif	
        return;
    }
    sprintf(fname,"%s",LP_getdatadir());
#ifdef _WIN32
    strcat(fname,"\\");
#else
    strcat(fname,"/");
#endif
    if ( strcmp(symbol,"BTC") == 0 )
    {
#if defined(__APPLE__) || defined(NATIVE_WINDOWS)
        strcat(fname,"Bitcoin");
#else
        strcat(fname,".bitcoin");
#endif
    }
    else if ( name != 0 )
    {
        char name2[64];
#if defined(__APPLE__) || defined(NATIVE_WINDOWS)
        int32_t len;
        strcpy(name2,name);
        name2[0] = toupper(name2[0]);
        len = (int32_t)strlen(name2);
        if ( strcmp(&name2[len-4],"coin") == 0 )
            name2[len - 4] = 'C';
#else
        name2[0] = '.';
        strcpy(name2+1,name);
#endif
       strcat(fname,name2);
    }
    else
    {
#if defined(__APPLE__) || defined(NATIVE_WINDOWS)
        strcat(fname,"Komodo");
#else
        strcat(fname,".komodo");
#endif
        if ( strcmp(symbol,"KMD") != 0 )
        {
#ifdef _WIN32
            strcat(fname,"\\");
#else
            strcat(fname,"/");
#endif
            strcat(fname,assetname);
        }
    }
#ifdef _WIN32
    strcat(fname,"\\");
#else
    strcat(fname,"/");
#endif
    strcat(fname,str);
}

uint16_t LP_userpass(char *userpass,char *symbol,char *assetname,char *confroot,char *name,char *confpath,uint16_t origport)
{
    FILE *fp; char fname[512],username[512],password[512],confname[512]; uint16_t port = 0;
    userpass[0] = 0;
    sprintf(confname,"%s.conf",confroot);
    if ( 0 )
        printf("%s (%s) %s confname.(%s) confroot.(%s)\n",symbol,assetname,name,confname,confroot);
#if defined(__APPLE__) || defined(NATIVE_WINDOWS)
    int32_t len;
    confname[0] = toupper(confname[0]);
    len = (int32_t)strlen(confname);
    if ( strcmp(&confname[len-4],"coin") == 0 )
        confname[len - 4] = 'C';
#endif
    LP_statefname(fname,symbol,assetname,confname,name,confpath);
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        if ( (port= LP_userpassfp(symbol,username,password,fp)) == 0 )
            port = origport;
        sprintf(userpass,"%s:%s",username,password);
        fclose(fp);
        if ( 0 )
            printf("LP_statefname.(%s) <- %s %s %s (%s) (%s)\n",fname,name,symbol,assetname,userpass,confpath);
        return(port);
    } else printf("cant open.(%s)\n",fname);
    return(origport);
}

cJSON *LP_coinjson(struct iguana_info *coin,int32_t showwif)
{
    struct electrum_info *ep; bits256 zero; int32_t notarized; uint64_t balance; char wifstr[128],ipaddr[72]; uint8_t tmptype; bits256 checkkey; cJSON *item = cJSON_CreateObject();
    jaddstr(item,"coin",coin->symbol);
    if ( showwif != 0 )
    {
        bitcoin_priv2wif(coin->symbol,coin->wiftaddr,wifstr,G.LP_privkey,coin->wiftype);
        bitcoin_wif2priv(coin->symbol,coin->wiftaddr,&tmptype,&checkkey,wifstr);
        if ( bits256_cmp(G.LP_privkey,checkkey) == 0 )
            jaddstr(item,"wif",wifstr);
        else jaddstr(item,"wif","error creating wif");
    }
    jadd(item,"installed",coin->userpass[0] == 0 ? jfalse() : jtrue());
    if ( coin->userpass[0] != 0 )
    {
        jaddnum(item,"height",LP_getheight(&notarized,coin));
        if ( notarized > 0 )
            jaddnum(item,"notarized",notarized);
        if ( coin->electrum != 0 )
            balance = LP_unspents_load(coin->symbol,coin->smartaddr);
        else balance = LP_RTsmartbalance(coin);
        jaddnum(item,"balance",dstr(balance));
        jaddnum(item,"KMDvalue",dstr(LP_KMDvalue(coin,balance)));
    }
#ifndef NOTETOMIC
    else if (coin->etomic[0] != 0) {
        int error = 0;
        if (coin->inactive == 0) {
            balance = LP_etomic_get_balance(coin, coin->smartaddr, &error);
        } else {
            balance = 0;
        }
        jaddnum(item,"height",-1);
        jaddnum(item,"balance",dstr(balance));
    }
#endif
    else
    {
        jaddnum(item,"height",-1);
        jaddnum(item,"balance",0);
    }
    if ( coin->inactive != 0 )
    {
        jaddstr(item,"status","inactive");
    }
    else jaddstr(item,"status","active");
    if ( coin->isPoS != 0 )
        jaddstr(item,"type","PoS");
    if ( (ep= coin->electrum) != 0 )
    {
        sprintf(ipaddr,"%s:%u",ep->ipaddr,ep->port);
        jaddstr(item,"electrum",ipaddr);
    }
    jaddstr(item,"smartaddress",coin->smartaddr);
    jaddstr(item,"rpc",coin->serverport);
    jaddnum(item,"pubtype",coin->pubtype);
    jaddnum(item,"p2shtype",coin->p2shtype);
    jaddnum(item,"wiftype",coin->wiftype);
    jaddnum(item,"txfee",strcmp(coin->symbol,"BTC") != 0 ? coin->txfee : LP_txfeecalc(coin,0,0));
    if ( strcmp(coin->symbol,"KMD") == 0 )
    {
        memset(zero.bytes,0,sizeof(zero));
        if ( strcmp(coin->smartaddr,coin->instantdex_address) != 0 )
        {
            LP_instantdex_depositadd(coin->smartaddr,zero);
            strcpy(coin->instantdex_address,coin->smartaddr);
        }
        jaddnum(item,"zcredits",dstr(LP_myzcredits()));
        jadd(item,"zdebits",LP_myzdebits());
    }
    return(item);
}

struct iguana_info *LP_conflicts_find(struct iguana_info *refcoin)
{
    struct iguana_info *coin=0,*tmp; int32_t n;
    if ( refcoin != 0 && (n= (int32_t)strlen(refcoin->serverport)) > 3 && strcmp(":80",&refcoin->serverport[n-3]) != 0 )
    {
        HASH_ITER(hh,LP_coins,coin,tmp)
        {
            if ( coin->inactive != 0 || coin->electrum != 0 || coin == refcoin )
                continue;
            if ( strcmp(coin->serverport,refcoin->serverport) == 0 )
                break;
        }
    }
    return(coin);
}

cJSON *LP_coinsjson(int32_t showwif)
{
    struct iguana_info *coin,*tmp; cJSON *array = cJSON_CreateArray();
    HASH_ITER(hh,LP_coins,coin,tmp)
    {
        jaddi(array,LP_coinjson(coin,showwif));
    }
    return(array);
}

char *LP_getcoin(char *symbol)
{
    int32_t numenabled,numdisabled; struct iguana_info *coin,*tmp; cJSON *item=0,*retjson;
    retjson = cJSON_CreateObject();
    if ( symbol != 0 && symbol[0] != 0 )
    {
        numenabled = numdisabled = 0;
        HASH_ITER(hh,LP_coins,coin,tmp)
        {
            if ( strcmp(symbol,coin->symbol) == 0 )
                item = LP_coinjson(coin,LP_showwif);
            if ( coin->inactive == 0 )
                numenabled++;
            else numdisabled++;
        }
        jaddstr(retjson,"result","success");
        jaddnum(retjson,"enabled",numenabled);
        jaddnum(retjson,"disabled",numdisabled);
        if ( item == 0 )
            item = cJSON_CreateObject();
        jadd(retjson,"coin",item);
    }
    return(jprint(retjson,1));
}

struct iguana_info *LP_coinsearch(char *symbol)
{
    struct iguana_info *coin = 0;
    if ( symbol != 0 && symbol[0] != 0 )
    {
        portable_mutex_lock(&LP_coinmutex);
        HASH_FIND(hh,LP_coins,symbol,strlen(symbol),coin);
        portable_mutex_unlock(&LP_coinmutex);
    }
    return(coin);
}

struct iguana_info *LP_coinadd(struct iguana_info *cdata)
{
    struct iguana_info *coin = calloc(1,sizeof(*coin));
    *coin = *cdata;
    portable_mutex_init(&coin->txmutex);
    portable_mutex_init(&coin->addrmutex);
    portable_mutex_init(&coin->addressutxo_mutex);
    portable_mutex_lock(&LP_coinmutex);
    HASH_ADD_KEYPTR(hh,LP_coins,coin->symbol,strlen(coin->symbol),coin);
    portable_mutex_unlock(&LP_coinmutex);
    strcpy(coin->validateaddress,"validateaddress");
    strcpy(coin->getinfostr,"getinfo");
    strcpy(coin->estimatefeestr,"estimatefee");
    return(coin);
}
*/

/// Adds a new currency into the list of currencies configured.
/// 
/// Returns an error if the currency already exists. Initializing the same currency twice is a bad habit
/// (might lead to misleading and confusing information during debugging and maintenance, see DRY)
/// and should be fixed on the call site.
/// 
/// NB: As of now only a part of coin information has been ported to `MmCoinEnum`, as much as necessary to fix the SWAP in #233.
///     We plan to port the rest of it later.
fn lp_coininit (ctx: &MmArc, ticker: &str) -> Result<MmCoinEnum, String> {
    let cctx = try_s! (CoinsContext::from_ctx (ctx));
    let mut coins = try_s! (cctx.coins.lock());
    let ve = match coins.raw_entry_mut().from_key (ticker) {
        RawEntryMut::Occupied (_oe) => return ERR! ("Coin {} already initialized", ticker),
        RawEntryMut::Vacant (ve) => ve
    };

    let coins = try_s! (ctx.conf["coins"].as_array().ok_or ("!coins"));
    let coins_en = coins.iter().find (|coin| coin["coin"].as_str() == Some (ticker)) .unwrap_or (&Json::Null);

    let c_ticker = try_s! (CString::new (ticker));
    let rpcport = match coins_en["rpcport"].as_u64() {
        Some (port) if port > 0 && port < u16::max_value() as u64 => port as u16,
        // NB: 0 for anything that's not "BTC" or "KMD".
        _ => unsafe {lp::LP_rpcport (c_ticker.as_ptr() as *mut c_char)}
    };

    let _estimatedrate = coins_en["estimatedrate"].as_f64().unwrap_or (20.);

    // NB: Unlike the previous C implementation we're never *moving* the `iguana_info` instance, it's effectively pinned.
    let mut ii: Box<lp::iguana_info> = Box::new (unsafe {zeroed()});
    // NB: Read values from local variables and not from `ii`
    //     (that is, to read A: let A = ...; ii.A = A; ii.B = ... A ...),
    //     allowing the compiler to verify the dependencies.
    // TODO: Maybe a *table* with hardcoded defaults, for readability?
    try_s! (safecopy! (ii.symbol, "{}", ticker));
    ii.txversion = coins_en["txversion"].as_i64().unwrap_or (if ticker == "PART" {160} else {1}) as i32;
    ii.updaterate = (now_ms() / 1000) as u32;
    ii.isPoS = coins_en["isPoS"].as_i64().unwrap_or (0) as u8;
    let taddr = coins_en["taddr"].as_u64().unwrap_or (0) as u8;
    ii.taddr = taddr;
    ii.wiftaddr = 0;
    ii.longestchain = 1;
    ii.txfee = coins_en["txfee"].as_u64().unwrap_or (if ticker == "BTC" {0} else {lp::LP_MIN_TXFEE as u64});
    ii.pubtype = coins_en["pubtype"].as_u64().unwrap_or (if ticker == "BTC" {0} else {60}) as u8;
    ii.p2shtype = coins_en["p2shtype"].as_u64().unwrap_or (if ticker == "BTC" {5} else {85}) as u8;
    ii.wiftype = coins_en["wiftype"].as_u64().unwrap_or (if ticker == "BTC" {128} else {188}) as u8;
    let inactive = loop {
        if ticker != "KMD" {
            if let Some (active) = coins_en["active"].as_i64() {
                if active != 0 {break 0}
        }   }
        break now_ms() / 1000
    };
    ii.inactive = inactive as u32;
    ii.ctx = unsafe {bitcoin_ctx() as *mut c_void};
    ii.noimportprivkey_flag = match ticker {"XVG" | "CLOAK" | "PPC" | "BCC" | "ORB" => 1, _ => 0};
    if rpcport != 0 {try_s! (safecopy! (ii.serverport, "127.0.0.1:{}", rpcport))}
    unsafe {lp::LP_coin_curl_init (&mut *ii)};
    ii.decimals = coins_en["decimals"].as_u64().unwrap_or (0) as u8;

    let asset = coins_en["asset"].as_str();
    let isassetchain = if let Some (asset) = asset {
        if asset != "BEER" && asset != "PIZZA" {
            ii.isassetchain = 1; 1
        } else {0}
    } else {0};

    ii.zcash = match ticker {
        "KMD" if isassetchain != 0 || taddr != 0 => lp::LP_IS_ZCASHPROTOCOL,
        "BCH" => lp::LP_IS_BITCOINCASH,
        "BTG" => lp::LP_IS_BITCOINGOLD,
        "CMM" => lp::LP_IS_BITCOINCASH,
        _ => 0
    } as u8;

    // NB: `LP_privkeycalc` initializes `lp::G.LP_privkey`, required to instantiate `UtxoCoin`.

    // NB: `LP_privkeycalc` triggers a chain of functions that ends up calling `LP_coinfind`, which tries to auto-add a coin.
    //     In order for this extra instance not to be added we have to make haste and add one ourselves.
    // Copies the `iguana_info` generated by `lp_coininit` into the old global `LP_coins`.
    let ii = Box::leak (ii);
    common::for_c::LP_coinadd (&mut *ii);

    let rpcport = unsafe {
        // TODO
        // The name/name2 logic here is a best-effort attempt to preserve the one in the former C code, but I think we should later simplify it.
        // These names are used to construct the file path, but that construction seems broken, at least on Windows (it's using a fixed USERHOME).
        // Maybe we should reuse the `komodo_conf_path` which provides the `c_confpath` value for the tests.
        let name = match ticker {
            "BTC" => "bitcoin",  // These were hardcoded before, though now for CMC we need the explicit "name" in the `coins` configuration as well.
            "KMD" => "komodo",
            _ => if let Some (asset) = asset {asset} else {coins_en["name"].as_str().unwrap_or ("")}
        };
        let name2 = if ticker == "KMD" || asset.is_some() {""} else {name};

        let c_asset = try_s! (CString::new (asset.unwrap_or ("")));
        let c_name = try_s! (CString::new (name));
        let c_name2 = try_s! (CString::new (name2));
        let c_confpath = try_s! (CString::new (coins_en["confpath"].as_str().unwrap_or ("")));
        lp::LP_userpass (
            ii.userpass.as_mut_ptr(),            // userpass
            c_ticker.as_ptr() as *mut c_char,    // symbol
            c_asset.as_ptr() as *mut c_char,     // assetname
            c_name.as_ptr() as *mut c_char,      // confroot
            c_name2.as_ptr() as *mut c_char,     // name
            c_confpath.as_ptr() as *mut c_char,  // confpath
            rpcport                              // origport
        )
    };
    if rpcport == 0 {log! ("Warning, coin " (ticker) " doesn't have the 'rpcport' configured")}

    // TODO: Move the private key into `MmCtx`. Initialize it before `lp_coininit`.
    let passphrase = try_s! (ctx.conf["passphrase"].as_str().ok_or ("!passphrase"));
    let c_passphrase = try_s! (CString::new (&passphrase[..]));
    unsafe {
        let mut pubkey33: [u8; 33] = zeroed();
        let mut pubkey: bits256 = zeroed();
        let pk = lp::LP_privkeycalc (
            ctx.btc_ctx() as *mut c_void,          // void *ctx
            pubkey33.as_mut_ptr(),                 // uint8_t *pubkey33
            &mut pubkey,                           // bits256 *pubkeyp
            &mut *ii,                              // struct iguana_info *coin
            c_passphrase.as_ptr() as *mut c_char,  // char *passphrase
            b"\0".as_ptr() as *mut c_char          // char *wifstr
        );
        if !pk.nonz() {return ERR! ("!LP_privkeycalc")}
        if !lp::G.LP_privkey.nonz() {return ERR! ("Error initializing the global private key (G.LP_privkey)")}
    }

    // TODO: Should pick the correct coin implementation somehow.
    let coin: MmCoinEnum = try_s! (coin_from_iguana_info (&mut *ii)) .into();

    ve.insert (ticker.into(), coin.clone());
    Ok (coin)
}

/*
uint16_t LP_coininit(struct iguana_info *coin,char *symbol,char *name,char *assetname,int32_t isPoS,uint16_t port,uint8_t pubtype,uint8_t p2shtype,uint8_t wiftype,uint64_t txfee,double estimatedrate,int32_t longestchain,uint8_t wiftaddr,uint8_t taddr,uint16_t busport,char *confpath,uint8_t decimals)
{
    static void *ctx;
    char *name2; uint16_t origport = port;
    memset(coin,0,sizeof(*coin));
    safecopy(coin->symbol,symbol,sizeof(coin->symbol));
    if ( strcmp(symbol,"PART") == 0 )
        coin->txversion = 160;
    else coin->txversion = 1;
    coin->updaterate = (uint32_t)time(NULL);
    coin->isPoS = isPoS;
    coin->taddr = taddr;
    coin->wiftaddr = wiftaddr;
    coin->longestchain = longestchain;
    if ( (coin->txfee= txfee) > 0 && txfee < LP_MIN_TXFEE )
        coin->txfee = LP_MIN_TXFEE;
    coin->pubtype = pubtype;
    coin->p2shtype = p2shtype;
    coin->wiftype = wiftype;
    coin->inactive = (uint32_t)time(NULL);
    //coin->bussock = LP_coinbus(busport);
    if ( ctx == 0 )
        ctx = bitcoin_ctx();
    coin->ctx = ctx;
    if ( assetname != 0 && strcmp(name,assetname) == 0 )
    {
        //printf("%s is assetchain\n",symbol);
        if ( strcmp(name,"BEER") != 0 && strcmp("PIZZA",name) != 0 )
            coin->isassetchain = 1;
    }
    if ( strcmp(symbol,"KMD") == 0 || (assetname != 0 && assetname[0] != 0) )
        name2 = 0;
    else name2 = name;
    if ( strcmp(symbol,"XVG") == 0 || strcmp(symbol,"CLOAK") == 0 || strcmp(symbol,"PPC") == 0 || strcmp(symbol,"BCC") == 0 || strcmp(symbol,"ORB") == 0 )
    {
        coin->noimportprivkey_flag = 1;
        printf("truncate importprivkey for %s\n",symbol);
    }
#ifndef FROM_JS
    port = LP_userpass(coin->userpass,symbol,assetname,name,name2,confpath,port);
#endif
    sprintf(coin->serverport,"127.0.0.1:%u",port);
    if ( port != origport )
        printf("set curl path for %s to %s\n",symbol,coin->serverport);
    if ( strcmp(symbol,"KMD") == 0 || coin->isassetchain != 0 || taddr != 0 )
        coin->zcash = LP_IS_ZCASHPROTOCOL;
    else if ( strcmp(symbol,"BCH") == 0 )
    {
        coin->zcash = LP_IS_BITCOINCASH;
        //printf("set coin.%s <- LP_IS_BITCOINCASH %d\n",symbol,coin->zcash);
    }
    else if ( strcmp(symbol,"BTG") == 0 )
    {
        coin->zcash = LP_IS_BITCOINGOLD;
        printf("set coin.%s <- LP_IS_BITCOINGOLD %d\n",symbol,coin->zcash);
    }
    else if ( strcmp(symbol,"CMM") == 0 )
    {
        coin->zcash = LP_IS_BITCOINCASH;
        //printf("set coin.%s <- LP_IS_BITCOINCASH %d\n",symbol,coin->zcash);
    }
    coin->curl_handle = curl_easy_init();
    portable_mutex_init(&coin->curl_mutex);
    coin->decimals = decimals;
    return(port);
}

int32_t LP_isdisabled(char *base,char *rel)
{
    struct iguana_info *coin;
    if ( base != 0 && (coin= LP_coinsearch(base)) != 0 && coin->inactive != 0 )
        return(1);
    else if ( rel != 0 && (coin= LP_coinsearch(rel)) != 0 && coin->inactive != 0 )
        return(1);
    else return(0);
}
*/

/// NB: As of now only a part of coin information has been ported to `MmCoinEnum`, as much as necessary to fix the SWAP in #233.
///     We plan to port the rest of it later (in lp_initcoins, lp_coininit).
pub fn lp_coinfind (ctx: &MmArc, ticker: &str) -> Result<Option<MmCoinEnum>, String> {
    let cctx = try_s! (CoinsContext::from_ctx (ctx));
    let coins = try_s! (cctx.coins.lock());
    Ok (coins.get (ticker) .map (|coin| coin.clone()))
}

/*
struct iguana_info *LP_coinfind(char *symbol)
{
    struct iguana_info *coin,cdata; int32_t isinactive,isPoS,longestchain = 1; uint16_t port,busport; uint64_t txfee; double estimatedrate; uint8_t pubtype,p2shtype,wiftype; char *name,*assetname;
    if ( symbol == 0 || symbol[0] == 0 )
        return(0);
    if ( (coin= LP_coinsearch(symbol)) != 0 )
        return(coin);
    if ( (port= LP_rpcport(symbol)) == 0 )
        return(0);
    if ( (busport= LP_busport(port)) == 0 )
        return(0);
    isPoS = 0;
    txfee = LP_MIN_TXFEE;
    estimatedrate = 20;
    pubtype = 60;
    p2shtype = 85;
    wiftype = 188;
    assetname = "";
    if ( strcmp(symbol,"BTC") == 0 )
    {
        txfee = 0;
        estimatedrate = 300;
        pubtype = 0;
        p2shtype = 5;
        wiftype = 128;
        name = "bitcoin";
    }
    else if ( strcmp(symbol,"KMD") == 0 )
        name = "komodo";
    else return(0);
    port = LP_coininit(&cdata,symbol,name,assetname,isPoS,port,pubtype,p2shtype,wiftype,txfee,estimatedrate,longestchain,0,0,busport,0,0);
    if ( port == 0 )
        isinactive = 1;
    else isinactive = 0;
    if ( (coin= LP_coinadd(&cdata)) != 0 )
    {
        coin->inactive = isinactive * (uint32_t)time(NULL);
        /*if ( strcmp(symbol,"KMD") == 0 )
            coin->inactive = 0;
        else*/ if ( strcmp(symbol,"BTC") == 0 )
        {
            coin->inactive = (uint32_t)time(NULL) * !IAMLP;
            printf("BTC inactive.%u\n",coin->inactive);
        }
    }
    return(coin);
}

// "coins":[{"coin":"<assetchain>", "rpcport":pppp}, {"coin":"LTC", "name":"litecoin", "rpcport":9332, "pubtype":48, "p2shtype":5, "wiftype":176, "txfee":100000 }]
// {"coin":"HUSH", "name":"hush", "rpcport":8822, "taddr":28, "pubtype":184, "p2shtype":189, "wiftype":128, "txfee":10000 }

struct iguana_info *LP_coincreate(cJSON *item)
{
    struct iguana_info cdata,*coin=0; int32_t isPoS,longestchain = 1; uint16_t port; uint64_t txfee; double estimatedrate; uint8_t pubtype,p2shtype,wiftype; char *name=0,*symbol,*assetname=0;
    if ( (symbol= jstr(item,"coin")) != 0 && symbol[0] != 0 && strlen(symbol) < 16 && LP_coinfind(symbol) == 0 && (port= juint(item,"rpcport")) != 0 )
    {
        isPoS = jint(item,"isPoS");
        txfee = j64bits(item,"txfee");
        if ( (estimatedrate= jdouble(item,"estimatedrate")) == 0. )
            estimatedrate = 20;
        pubtype = juint(item,"pubtype");
        if ( (p2shtype= juint(item,"p2shtype")) == 0 )
            p2shtype = 85;
        if ( (wiftype= juint(item,"wiftype")) == 0 )
            wiftype = 188;
        if ( (assetname= jstr(item,"asset")) != 0 )
        {
            name = assetname;
            pubtype = 60;
        }
        else if ( (name= jstr(item,"name")) == 0 )
            name = symbol;

        uint8_t decimals = juint(item,"decimals");
        if ( LP_coininit(&cdata,symbol,name,assetname==0?"":assetname,isPoS,port,pubtype,p2shtype,wiftype,txfee,estimatedrate,longestchain,juint(item,"wiftaddr"),juint(item,"taddr"),LP_busport(port),jstr(item,"confpath"),decimals) < 0 )
        {
            coin = LP_coinadd(&cdata);
            coin->inactive = (uint32_t)time(NULL);
        } else coin = LP_coinadd(&cdata);
    } else if ( symbol != 0 && jobj(item,"rpcport") == 0 )
        printf("SKIP %s, missing rpcport field in coins array\n",symbol);
    if ( coin != 0 && item != 0 )
    {
        if ( strcmp("KMD",coin->symbol) != 0 )
        {
            if ( jobj(item,"active") != 0 )
                coin->inactive = !jint(item,"active");
            else
            {
                if ( IAMLP == 0 || assetname != name )
                    coin->inactive = (uint32_t)time(NULL);
                else coin->inactive = 0;
            }
        } else coin->inactive = 0;
    }
    if ( 0 && coin != 0 && coin->inactive != 0 )
        printf("LPnode.%d %s inactive.%u %p vs %p\n",IAMLP,coin->symbol,coin->inactive,assetname,name);
    return(0);
}

void LP_otheraddress(char *destcoin,char *otheraddr,char *srccoin,char *coinaddr)
{
    uint8_t addrtype,rmd160[20]; struct iguana_info *src,*dest;
    if ( (src= LP_coinfind(srccoin)) != 0 && (dest= LP_coinfind(destcoin)) != 0 )
    {
        bitcoin_addr2rmd160(srccoin,src->taddr,&addrtype,rmd160,coinaddr);
        bitcoin_address(destcoin,otheraddr,dest->taddr,dest->pubtype,rmd160,20);
    } else printf("couldnt find %s or %s\n",srccoin,destcoin);
}
*/

pub fn lp_initcoins (ctx: &MmArc) -> Result<(), String> {
    // The function lived in the "LP_nativeDEX.c" originally, but I suspect that we can have it encapsulated in the `coins` proper.

    // A special case for default coins?
    // TODO: Can we refactor the default and the configured coins into a single loop?
    for &ticker in ["BTC", "KMD"].iter() {
        let _coin_enum = match lp_coininit (ctx, ticker) {
            Ok (t) => t,
            Err (err) => return ERR! ("lp_coininit error: {}", err),
        };

        let c_ticker = try_s! (CString::new (ticker));
        let c_ticker = c_ticker.as_ptr() as *mut c_char;
        let c_coin = unsafe {lp::LP_coinfind (c_ticker)};
        if c_coin.is_null() {return ERR! ("Error creating a coin instance for {}", ticker)}
        let coin: &mut lp::iguana_info = unsafe {&mut *c_coin};
        assert_eq! (ticker, unwrap! (unsafe {CStr::from_ptr (coin.symbol.as_ptr())} .to_str()));

        let _price_info = unsafe {lp::LP_priceinfoadd (c_ticker)};
        assert_eq! (unsafe {lp::LP_coinfind (c_ticker)}, c_coin);

        let mut notarized = 0;
        if unsafe {lp::LP_getheight (&mut notarized, coin)} <= 0 {
            coin.inactive = (now_ms() / 1000) as u32
        } else {
            unsafe {lp::LP_unspents_load (coin.symbol.as_mut_ptr(), coin.smartaddr.as_mut_ptr())};
            if ticker == "KMD" {
                unsafe {lp::LP_importaddress (b"KMD\0".as_ptr() as *mut c_char, lp::BOTS_BONDADDRESS.as_ptr() as *mut c_char)};
                unsafe {lp::LP_dPoW_request (c_coin)};
            }
        }

        if coin.txfee == 0 && ticker != "BTC" {
            coin.txfee = lp::LP_MIN_TXFEE as u64
        }
    }

    for coins_en in ctx.conf["coins"].as_array().map (|v| v.iter()) .unwrap_or (Vec::new().iter()) {
        let ticker = match coins_en["coin"].as_str() {
            Some (ticker) => ticker,
            None => {log! ("lp_initcoins] Skipping a coin entry lacking the ticker symbol field 'coin': " [coins_en]); continue}
        };

        // Triggered in test_autoprice_coinmarketcap.
        // TODO: We should merge these loops instead.
        if ticker == "BTC" || ticker == "KMD" {continue}

        let _coin_enum = match lp_coininit (ctx, ticker) {
            Ok (t) => t,
            Err (err) => return ERR! ("lp_coininit error: {}", err),
        };

        let c_ticker = try_s! (CString::new (ticker));
        let c_ticker = c_ticker.as_ptr() as *mut c_char;
        let c_coin = unsafe {lp::LP_coinfind (c_ticker)};
        if c_coin.is_null() {
            // NB: Not fatal for now, because slim configurations like {"coin": "LTC", "name": "litecoin"}
            // don't have enough information for the `LP_coins` entry but can still be useful
            // for ticker<->name conversions (cf. `fn test_autoprice_coinmarketcap`).
            log! ("Error creating the `LP_coins` entry for " (ticker));
            continue
        }
        let coin: &mut lp::iguana_info = unsafe {&mut *c_coin};
        assert_eq! (ticker, unwrap! (unsafe {CStr::from_ptr (coin.symbol.as_ptr())} .to_str()));

        unsafe {lp::LP_priceinfoadd (c_ticker)};
        assert_eq! (unsafe {lp::LP_coinfind (c_ticker)}, c_coin);

        // TODO: Move to lp_coininit.
        if !coins_en["etomic"].is_null() {
            let etomic = match coins_en["etomic"].as_str() {Some (s) => s, None => return ERR! ("Field 'etomic' is not a string")};
            try_s! (safecopy! (coin.etomic, "{}", etomic));
        } else {
            let mut notarized = 0;
            if unsafe {lp::LP_getheight (&mut notarized, coin)} <= 0 {
                coin.inactive = (now_ms() / 1000) as u32
            } else {
                unsafe {lp::LP_unspents_load (coin.symbol.as_mut_ptr(), coin.smartaddr.as_mut_ptr())};
            }

            if coin.txfee == 0 && ticker != "BTC" {
                coin.txfee = lp::LP_MIN_TXFEE as u64
            }
        }
    }

    // List the coins we've initialized.
    let mut coins = Vec::new();
    try_s! (unsafe {common::coins_iter (lp::LP_coins, &mut |coin| {coins.push (CStr::from_ptr ((*coin).symbol.as_ptr())); Ok(())})});
    log! ("lp_initcoins] Finished with: " for coin in coins {(unwrap! (coin.to_str()))} separated {", "} '.');

    Ok(())
}
