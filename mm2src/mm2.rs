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
//  mm2.rs
//  marketmaker
//
//  Copyright © 2017-2018 SuperNET. All rights reserved.
//

#![allow(non_camel_case_types)]

extern crate crc;

#[allow(unused_imports)]
#[macro_use]
extern crate duct;

#[cfg(feature = "etomic")]
extern crate etomicrs;

#[macro_use]
extern crate fomat_macros;

extern crate futures;
extern crate futures_cpupool;

#[macro_use]
extern crate gstuff;

extern crate helpers;

extern crate hyper;

#[allow(unused_imports)]
#[macro_use]
extern crate lazy_static;

extern crate libc;

extern crate nix;

extern crate portfolio;

extern crate rand;

extern crate serde;

#[allow(unused_imports)]
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate unwrap;

extern crate winapi;

extern crate tokio_core;

// Re-export preserves the functions that are temporarily accessed from C during the gradual port.
#[cfg(feature = "etomic")]
pub use etomicrs::*;

use gstuff::now_ms;

use helpers::{bitcoin_ctx, bitcoin_priv2wif, lp, os, stack_trace, stack_trace_frame, BitcoinCtx, CJSON, MM_VERSION};
use helpers::lp::{_bits256 as bits256};

use rand::random;

use serde_json::{self as json, Value as Json};

use std::env;
use std::ffi::{CStr, CString, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::raw::{c_char, c_int, c_void};
use std::mem::{zeroed};
use std::path::Path;
use std::process::exit;
use std::ptr::{null};
use std::str::from_utf8_unchecked;
use std::slice::from_raw_parts;
use std::thread::sleep;
use std::time::Duration;
use std::str;

pub mod crash_reports;
mod lp_native_dex;
use lp_native_dex::{lp_init};

pub mod rpc;

use crash_reports::init_crash_reports;

/*
#include "LP_nativeDEX.c"

void LP_ports(uint16_t *pullportp,uint16_t *pubportp,uint16_t *busportp,uint16_t netid)
{
    int32_t netmod,netdiv; uint16_t otherports;
    *pullportp = *pubportp = *busportp = 0;
    if ( netid < 0 )
        netid = 0;
    else if ( netid > (65535-40-LP_RPCPORT)/4 )
    {
        printf("netid.%d overflow vs max netid.%d 14420?\n",netid,(65535-40-LP_RPCPORT)/4);
        exit(-1);
    }
    if ( netid != 0 )
    {
        netmod = (netid % 10);
        netdiv = (netid / 10);
        otherports = (netdiv * 40) + (LP_RPCPORT + netmod);
    } else otherports = LP_RPCPORT;
    *pullportp = otherports + 10;
    *pubportp = otherports + 20;
    *busportp = otherports + 30;
    printf("RPCport.%d remoteport.%d, nanoports %d %d %d\n",RPC_port,RPC_port-1,*pullportp,*pubportp,*busportp);
}
*/
fn lp_main (c_conf: CJSON, conf: Json) -> Result<(), String> {
    // Redirects the C stdout to the log.
    let c_log_path_buf: CString;
    let c_log_path = if conf["log"].is_null() {null()} else {
        let log = try_s! (conf["log"].as_str().ok_or ("log is not a string"));
        c_log_path_buf = try_s! (CString::new (log));
        c_log_path_buf.as_ptr()
    };
    unsafe {lp::unbuffered_output_support (c_log_path)};

    let (mut pullport, mut pubport, mut busport) = (0, 0, 0);
    if conf["passphrase"].is_string() {
        let profitmargin = conf["profitmargin"].as_f64();
        unsafe {lp::LP_profitratio += profitmargin.unwrap_or (0.)};
        let port = conf["rpcport"].as_u64().unwrap_or (lp::LP_RPCPORT as u64);
        if port < 1000 {return ERR! ("port < 1000")}
        if port > u16::max_value() as u64 {return ERR! ("port > u16")}
        let netid = conf["netid"].as_u64().unwrap_or (0) as u16;
        unsafe {lp::LP_ports (&mut pullport, &mut pubport, &mut busport, netid)};
        let client = conf["client"].as_i64().unwrap_or (0);
        if client < i32::min_value() as i64 {return ERR! ("client < i32")}
        if client > i32::max_value() as i64 {return ERR! ("client > i32")}
        try_s! (lp_init (port as u16, pullport, pubport, client == 1, conf, c_conf));
        Ok(())
    } else {ERR! ("!passphrase")}
}

fn global_dbdir() -> &'static Path {
    Path::new (unwrap! (unsafe {CStr::from_ptr (lp::GLOBAL_DBDIR.as_ptr())} .to_str()))
}

/// Invokes `OS_ensure_directory`,  
/// then prints an error and returns `false` if the directory is not writeable.
fn ensure_writable (dir_path: &Path) -> bool {
    let c_dir_path = unwrap! (dir_path.to_str());
    let c_dir_path = unwrap! (CString::new (c_dir_path));
    unsafe {os::OS_ensure_directory (c_dir_path.as_ptr() as *mut c_char)};

    /*
    char fname[512],str[65],str2[65]; bits256 r,check; FILE *fp;
    */
    let r: [u8; 32] = random();
    let mut check: Vec<u8> = Vec::with_capacity (r.len());
    let fname = dir_path.join ("checkval");
    let mut fp = match fs::File::create (&fname) {
        Ok (fp) => fp,
        Err (_) => {
            eprintln! ("FATAL ERROR cant create {:?}", fname);
            return false
        }
    };
    if fp.write_all (&r) .is_err() {
        eprintln! ("FATAL ERROR writing {:?}", fname);
        return false
    }
    drop (fp);
    let mut fp = match fs::File::open (&fname) {
        Ok (fp) => fp,
        Err (_) => {
            eprintln! ("FATAL ERROR cant open {:?}", fname);
            return false
        }
    };
    if fp.read_to_end (&mut check).is_err() || check.len() != r.len() {
        eprintln! ("FATAL ERROR reading {:?}", fname);
        return false
    }
    if check != r {
        eprintln! ("FATAL ERROR error comparing {:?} {:?} vs {:?}", fname, r, check);
        return false
    }
    true
}

#[cfg(test)]
mod test {
    use gstuff::{now_float, slurp};

    use helpers::for_tests::{MarketMakerIt, RaiiKill};

    use hyper::StatusCode;

    use serde_json::{self as json, Value as Json};

    use std::env;
    use std::ffi::CString;
    use std::fs;
    use std::os::raw::c_char;
    use std::path::{Path, PathBuf};
    use std::str::{from_utf8_unchecked};
    use std::thread::{self, sleep};
    use std::time::Duration;

    /// Integration test for the "autoprice" mode.
    /// Starts MM in background and files a buy request with it, in the "autoprice" mode,
    /// then checks the logs to see that the price fetching code works.
    #[test]
    fn test_autoprice() {
        // One of the ways we want to test the MarketMaker in the integration tests is by reading the logs.
        // Just like the end users, we learn of what's MarketMaker doing from the logs,
        // the information in the logs is actually a part of the user-visible functionality,
        // it should be readable, there should be enough information for both the users and the GUI to understand what's going on
        // and to make an informed decision about whether the MarketMaker is performing correctly.

        let passphrase = "SPATsRps3dhEtXwtnpRCKF";
        let mm = unwrap! (MarketMakerIt::start (
            json! ({
                "gui": "nogui",
                "client": 1,
                "passphrase": passphrase,
                "coins": [
                    {"coin": "BEER","asset": "BEER", "rpcport": 8923},
                    {"coin": "PIZZA","asset": "PIZZA", "rpcport": 11116}
                ]
            }),
            "aa503e7d7426ba8ce7f6627e066b04bf06004a41fd281e70690b3dbc6e066f69".into(),
            local_start));
        println! ("test_autoprice] `mm2` log: {:?}.", mm.log_path);
        unwrap! (mm.wait_for_log (19., &|log| log.contains (">>>>>>>>> DEX stats ")));

        // Enable the currencies (fresh list of servers at https://github.com/jl777/coins/blob/master/electrums/BEER).
        let electrum_beer = unwrap! (mm.rpc (json! ({
            "userpass": mm.userpass,
            "method": "electrum",
            "coin": "BEER",
            "ipaddr": "electrum1.cipig.net",
            "port": 10022
        })));
        assert_eq! (electrum_beer.0, StatusCode::OK);

        let electrum_pizza = unwrap! (mm.rpc (json! ({
            "userpass": mm.userpass,
            "method": "electrum",
            "coin": "PIZZA",
            "ipaddr": "electrum1.cipig.net",
            "port": 10024
        })));
        assert_eq! (electrum_pizza.0, StatusCode::OK);

        let address = unwrap! (mm.rpc (json! ({
            "userpass": mm.userpass,
            "method": "calcaddress",
            "passphrase": passphrase
        })));
        assert_eq! (address.0, StatusCode::OK);
        let address: Json = unwrap! (json::from_str (&address.1));
        println! ("test_autoprice] coinaddr: {}.", unwrap! (address["coinaddr"].as_str(), "!coinaddr"));

        // Trigger the autoprice.

        let autoprice = unwrap! (mm.rpc (json! ({
            "userpass": mm.userpass,
            "method": "autoprice",
            "base": "PIZZA",
            "rel": "BEER",
            "margin": 0.5
        })));
        assert_eq! (autoprice.0, StatusCode::OK);
        unwrap! (mm.wait_for_log (99., &|log| log.contains ("Waiting for Bittrex market summaries... Ok.")));
        unwrap! (mm.wait_for_log (9., &|log| log.contains ("Waiting for Cryptopia markets... Ok.")));

        // Checking the autopricing logs here TDD-helps us with the porting effort.
        //
        // The logging format is in flux until we start exporting the logs to websocket using them from HyperDEX.
        // And the stdout format can be changed even after that.

        unwrap! (mm.stop());

        // See if `LogState` is properly dropped, which is needed in order to log the remaining dashboard entries.
        unwrap! (mm.wait_for_log (9., &|log| log.contains ("rpc] on_stop, firing shutdown_tx!")));
        unwrap! (mm.wait_for_log (9., &|log| log.contains ("LogState] drop!")));
    }

    /// Integration test for RPC server.
    /// Check that MM doesn't crash in case of invalid RPC requests
    #[test]
    fn test_rpc() {
        let passphrase = "SPATsRps3dhEtXwtnpRCKF";
        let mm = unwrap! (MarketMakerIt::start (
            json! ({
                "gui": "nogui",
                "client": 1,
                "passphrase": passphrase,
                "coins": [
                    {"coin": "BEER","asset": "BEER", "rpcport": 8923},
                    {"coin": "PIZZA","asset": "PIZZA", "rpcport": 11116}
                ]
            }),
            "aa503e7d7426ba8ce7f6627e066b04bf06004a41fd281e70690b3dbc6e066f69".into(),
            local_start));
        println! ("test_rpc] `mm2` log: {:?}.", mm.log_path);
        unwrap! (mm.wait_for_log (19., &|log| log.contains (">>>>>>>>> DEX stats ")));

        let no_method = unwrap! (mm.rpc (json! ({
            "userpass": mm.userpass,
            "coin": "BEER",
            "ipaddr": "electrum1.cipig.net",
            "port": 10022
        })));
        assert! (no_method.0.is_client_error());

        let not_json = unwrap! (mm.rpc_str("It's just a string"));
        assert! (not_json.0.is_client_error());

        let unknown_method = unwrap! (mm.rpc (json! ({
            "method": "unknown_method",
        })));

        assert_eq! (unknown_method.0, StatusCode::OK);

        unwrap! (mm.stop());
    }

    use super::{btc2kmd, events, lp_main, CJSON};

    /// Integration (?) test for the "btc2kmd" command line invocation.
    /// The argument is the WIF example from https://en.bitcoin.it/wiki/Wallet_import_format.
    #[test]
    fn test_btc2kmd() {
        let output = unwrap! (btc2kmd ("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"));
        assert_eq! (output, "BTC 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ \
        -> KMD UpRBUQtkA5WqFnSztd7sCYyyhtd4aq6AggQ9sXFh2fXeSnLHtd3Z: \
        privkey 0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
    }

    /// This is not a separate test but a helper used by `MarketMakerIt` to run the MarketMaker from the test binary.
    #[test]
    fn test_mm_start() {
        if let Ok (conf) = env::var ("_MM2_TEST_CONF") {
            println! ("test_mm_start] Starting the MarketMaker...");
            let conf: Json = unwrap! (json::from_str (&conf));
            let c_json = unwrap! (CString::new (unwrap! (json::to_string (&conf))));
            let c_conf = unwrap! (CJSON::from_zero_terminated (c_json.as_ptr() as *const c_char));
            unwrap! (lp_main (c_conf, conf))
        }
    }

    #[cfg(windows)]
    fn chdir (dir: &Path) {
        use winapi::um::processenv::SetCurrentDirectoryA;

        let dir = unwrap! (dir.to_str());
        let dir = unwrap! (CString::new (dir));
        // https://docs.microsoft.com/en-us/windows/desktop/api/WinBase/nf-winbase-setcurrentdirectory
        let rc = unsafe {SetCurrentDirectoryA (dir.as_ptr())};
        assert_ne! (rc, 0);
    }

    #[cfg(not(windows))]
    fn chdir (_dir: &Path) {panic! ("chdir not implemented")}

    /// Used by `MarketMakerIt` when the `LOCAL_THREAD_MM` env is `1`, helping debug the tested MM.
    fn local_start (folder: PathBuf, log_path: PathBuf, mut conf: Json) {
        unwrap! (thread::Builder::new().name ("MM".into()) .spawn (move || {
            if conf["log"].is_null() {
                conf["log"] = unwrap! (log_path.to_str()) .into();
            } else {
                let path = Path::new (unwrap! (conf["log"].as_str(), "log is not a string"));
                assert_eq! (log_path, path);
            }

            println! ("local_start] MM in a thread, log {:?}.", log_path);

            chdir (&folder);

            let c_json = unwrap! (CString::new (unwrap! (json::to_string (&conf))));
            let c_conf = unwrap! (CJSON::from_zero_terminated (c_json.as_ptr() as *const c_char));
            unwrap! (lp_main (c_conf, conf))
        }));
    }

    /// Integration test for the "mm2 events" mode.
    /// Starts MM in background and verifies that "mm2 events" produces a non-empty feed of events.
    #[test]
    fn test_events() {
        let executable = unwrap! (env::args().next());
        let executable = unwrap! (Path::new (&executable) .canonicalize());
        let mm_events_output = env::temp_dir().join ("test_events.mm_events.log");
        match env::var ("_MM2_TEST_EVENTS_MODE") {
            Ok (ref mode) if mode == "MM_EVENTS" => {
                println! ("test_events] Starting the `mm2 events`...");
                unwrap! (events (&["_test".into(), "events".into()]));
            },
            _ => {
                let mut mm = unwrap! (MarketMakerIt::start (
                    json! ({"gui": "nogui", "client": 1, "passphrase": "123", "coins": "BTC,KMD"}),
                    "5bfaeae675f043461416861c3558146bf7623526891d890dc96bc5e0e5dbc337".into(),
                    local_start));
                println! ("test_events] `mm2` log: {:?}.", mm.log_path);

                println! ("test_events] `mm2 events` log: {:?}.", mm_events_output);
                let mut mm_events = RaiiKill::from_handle (unwrap! (cmd! (executable, "test_events", "--nocapture")
                    .env ("_MM2_TEST_EVENTS_MODE", "MM_EVENTS")
                    .env ("MM2_UNBUFFERED_OUTPUT", "1")
                    .stderr_to_stdout().stdout (&mm_events_output) .start()));

                #[derive(Debug)] enum MmState {Starting, Started, GetendpointSent, Passed}
                let mut mm_state = MmState::Starting;

                // Monitor the MM output.
                let started = now_float();
                loop {
                    if let Some (ref mut pc) = mm.pc {if !pc.running() {panic! ("MM process terminated prematurely.")}}
                    if !mm_events.running() {panic! ("`mm2 events` terminated prematurely.")}

                    mm_state = match mm_state {
                        MmState::Starting => {  // See if MM started.
                            let mm_log = unwrap! (mm.log_as_utf8());
                            let expected_bind = format! (">>>>>>>>> DEX stats {}:7783", mm.ip);
                            if mm_log.contains (&expected_bind) {MmState::Started}
                            else {MmState::Starting}
                        },
                        MmState::Started => {  // Kickstart the events stream by invoking the "getendpoint".
                            let (status, body) = unwrap! (mm.rpc (json! (
                                {"userpass": mm.userpass, "method": "getendpoint"})));
                            println! ("test_events] getendpoint response: {:?}, {}", status, body);
                            assert_eq! (status, StatusCode::OK);
                            //let expected_endpoint = format! ("\"endpoint\":\"ws://{}:5555\"", mm.ip);
                            assert! (body.contains ("\"endpoint\":\"ws://127.0.0.1:5555\""), "{}", body);
                            MmState::GetendpointSent
                        },
                        MmState::GetendpointSent => {  // Wait for the `mm2 events` test to finish.
                            let mm_events_log = slurp (&mm_events_output);
                            let mm_events_log = unsafe {from_utf8_unchecked (&mm_events_log)};
                            if mm_events_log.contains ("\"base\":\"KMD\"") && mm_events_log.contains ("\"price64\":\"") {MmState::Passed}
                            else {MmState::GetendpointSent}
                        },
                        MmState::Passed => {  // Gracefully stop the MM.
                            unwrap! (mm.stop());
                            sleep (Duration::from_millis (100));
                            let _ = fs::remove_file (mm_events_output);
                            break
                        }
                    };

                    if now_float() - started > 60. {
                        println! ("--- mm2.log ---\n{}\n", unwrap! (mm.log_as_utf8()));
                        panic! ("Test didn't pass withing the 60 seconds timeframe. mm_state={:?}", mm_state)}
                    sleep (Duration::from_millis (20))
                }
            }
        }
    }
}

fn help() {
    pintln! (
        "Command-line options.\n"
        "The first command-line argument is special and designates the mode.\n"
        "\n"
        "  help                  ..  Display this message.\n"
        "  btc2kmd {WIF or BTC}  ..  Convert a BTC WIF into a KMD WIF.\n"
        "  events                ..  Listen to a feed coming from a separate MM daemon and print it to stdout.\n"
        "  vanity {substring}    ..  Tries to find an address with the given substring.\n"
        "  nxt                   ..  Query the local NXT client (port 7876) regarding the SuperNET account in NXT.\n"
        "  {JSON configuration}  ..  Run the MarketMaker daemon.\n"
        "\n"
        "Some (but not all) of the JSON configuration parameters (* - required):\n"
        "\n"
        "  alice_contract ..  0x prefixed Alice ETH contract address.\n"
        "                     Default is 0x9bc5418ceded51db08467fc4b62f32c5d9ebda55 (Mainnet).\n"
        "                     Set 0xe1d4236c5774d35dc47dcc2e5e0ccfc463a3289c for Ropsten testnet\n"
        "  bob_contract   ..  0x prefixed Bob ETH contract address.\n"
        "                     Default is 0xfef736cfa3b884669a4e0efd6a081250cce228e7 (Mainnet).\n"
        "                     Set 0x2a8e4f9ae69c86e277602c6802085febc4bd5986 for Ropsten testnet\n"
        "  canbind        ..  If > 1000 and < 65536, initializes the `LP_fixed_pairport`.\n"
        "  client         ..  '1' to use the client mode.\n"
        "  ethnode        ..  HTTP url of ethereum node. Parity ONLY. Default is http://195.201.0.6:8555 (Mainnet).\n"
        "                     Set http://195.201.0.6:8545 for Ropsten testnet.\n"
        "  log            ..  File path. Redirect (as of now only a part of) the log there.\n"
        "  myipaddr       ..  IP address to bind to for P2P networking.\n"
        "  netid          ..  Subnetwork. Affects ports and keys.\n"
        "  passphrase *   ..  Wallet seed.\n"
        "  profitmargin   ..  Adds to `LP_profitratio`.\n"
        "  rpcip          ..  IP address to bind to for RPC server. Overrides the 127.0.0.1 default\n"
        "  rpcport        ..  If > 1000 overrides the 7783 default.\n"
        "  userhome       ..  Writable folder with MM files ('DB' by default).\n"
        "  wif            ..  `1` to add WIFs to the information we provide about a coin.\n"
        "\n"
        // Generated from https://github.com/KomodoPlatform/Documentation (PR to dev branch).
        // SHossain: "this would be the URL we would recommend and it will be maintained
        //            Please let @gcharang or me know if anything needs updating there".
        "See also the online documentation at https://docs.komodoplatform.com/barterDEX/barterDEX-API.html."
    )
}

fn main() {
    init_crash_reports();
    unsafe {os::OS_init()};
    println!("BarterDEX MarketMaker {} \n", MM_VERSION);

    // Temporarily simulate `argv[]` for the C version of the main method.
    let args: Vec<String> = env::args().map (|mut arg| {arg.push ('\0'); arg}) .collect();
    let mut args: Vec<*const c_char> = args.iter().map (|s| s.as_ptr() as *const c_char) .collect();
    args.push (null());

    let args_os: Vec<OsString> = env::args_os().collect();

    // NB: The first argument is special, being used as the mode switcher.
    // The other arguments might be used to pass the data to the various MM modes,
    // we're not checking them for the mode switches in order not to risk [untrusted] data being mistaken for a mode switch.
    let first_arg = args_os.get (1) .and_then (|arg| arg.to_str());

    if first_arg == Some ("btc2kmd") && args_os.get (2) .is_some() {
        match btc2kmd (unwrap! (args_os[2].to_str(), "Bad argument encoding")) {
            Ok (output) => println! ("{}", output),
            Err (err) => eprintln! ("btc2kmd error] {}", err)
        }
        return
    }

    if let Err (err) = events (&args_os) {eprintln! ("events error] {}", err); return}

    let second_arg = args_os.get (2) .and_then (|arg| arg.to_str());
    if first_arg == Some ("vanity") && second_arg.is_some() {vanity (unwrap! (second_arg)); return}

    if first_arg == Some ("--help") || first_arg == Some ("-h") || first_arg == Some ("help") {help(); return}
    if cfg! (windows) && first_arg == Some ("/?") {help(); return}

    if !fix_directories() {eprintln! ("Some of the required directories are not accessible."); exit (1)}

    if first_arg == Some ("nxt") {
        unsafe {lp::LP_NXT_redeems()};
        sleep (Duration::from_secs (3));
        return
    }

    if let Some (conf) = first_arg {
        if let Err (err) = run_lp_main (conf) {
            eprintln! ("{}", err);
            exit (1);
        }
    }
}

// TODO: `btc2kmd` is *pure*, it doesn't use shared state,
// though some of the underlying functions (`LP_convaddress`) do (the hash of cryptocurrencies is shared).
// Should mark it as shallowly pure.

/// Implements the "btc2kmd" command line utility.
fn btc2kmd (wif_or_btc: &str) -> Result<String, String> {
    extern "C" {
        fn LP_wifstr_valid (symbol: *const u8, wifstr: *const u8) -> i32;
        fn LP_convaddress (symbol: *const u8, address: *const u8, dest: *const u8) -> *const c_char;
        fn bitcoin_wif2priv (symbol: *const u8, wiftaddr: u8, addrtypep: *mut u8, privkeyp: *mut bits256, wifstr: *const c_char) -> i32;
        fn bits256_cmp (a: bits256, b: bits256) -> i32;
    }

    let wif_or_btc_z = format! ("{}\0", wif_or_btc);
    /* (this line helps the IDE diff to match the old and new code)
    if ( strstr(argv[0],"btc2kmd") != 0 && argv[1] != 0 )
    */
    let mut privkey: bits256 = unsafe {zeroed()};
    let mut checkkey: bits256 = unsafe {zeroed()};
    let mut tmptype = 0;
    let mut kmdwif: [c_char; 64] = unsafe {zeroed()};
    if unsafe {LP_wifstr_valid (b"BTC\0".as_ptr(), wif_or_btc_z.as_ptr())} > 0 {
        let rc = unsafe {bitcoin_wif2priv (b"BTC\0".as_ptr(), 0, &mut tmptype, &mut privkey, wif_or_btc_z.as_ptr() as *const i8)};
        if rc < 0 {return ERR! ("!bitcoin_wif2priv")}
        let rc = unsafe {bitcoin_priv2wif (b"KMD\0".as_ptr(), 0, kmdwif.as_mut_ptr(), privkey, 188)};
        if rc < 0 {return ERR! ("!bitcoin_priv2wif")}
        let rc = unsafe {bitcoin_wif2priv (b"KMD\0".as_ptr(), 0, &mut tmptype, &mut checkkey, kmdwif.as_ptr())};
        if rc < 0 {return ERR! ("!bitcoin_wif2priv")}
        let kmdwif = try_s! (unsafe {CStr::from_ptr (kmdwif.as_ptr())} .to_str());
        if unsafe {bits256_cmp (privkey, checkkey)} == 0 {
            Ok (format! ("BTC {} -> KMD {}: privkey {}", wif_or_btc, kmdwif, privkey))
        } else {
            Err (format! ("ERROR BTC {} {} != KMD {} {}", wif_or_btc, privkey, kmdwif, checkkey))
        }
    } else {
        let retstr = unsafe {LP_convaddress(b"BTC\0".as_ptr(), wif_or_btc_z.as_ptr(), b"KMD\0".as_ptr())};
        if retstr == null() {return ERR! ("LP_convaddress")}
        Ok (unwrap! (unsafe {CStr::from_ptr (retstr)} .to_str()) .into())
    }
}

/// Implements the `mm2 events` mode.  
/// If the command-line arguments match the events mode and everything else works then this function will never return.
fn events (args_os: &[OsString]) -> Result<(), String> {
    use helpers::nn::*;

    /*
    else if ( argv[1] != 0 && strcmp(argv[1],"events") == 0 )
    */
    if args_os.get (1) .and_then (|arg| arg.to_str()) .unwrap_or ("") == "events" {
        let ipc_endpoint = unsafe {nn_socket (AF_SP as c_int, NN_PAIR as c_int)};
        if ipc_endpoint < 0 {return ERR! ("!nn_socket")}
        let rc = unsafe {nn_connect (ipc_endpoint, "ws://127.0.0.1:5555\0".as_ptr() as *const c_char)};
        if rc < 0 {return ERR! ("!nn_connect")}
        loop {
            let mut buf: [u8; 1000000] = unsafe {zeroed()};
            let len = unsafe {nn_recv (ipc_endpoint, buf.as_mut_ptr() as *mut c_void, buf.len() - 1, 0)};
            if len >= 0 {
                let len = len as usize;
                assert! (len < buf.len());
                let stdout = io::stdout();
                let mut stdout = stdout.lock();
                try_s! (stdout.write_all (&buf[0..len]));
            }
        }
    }
    Ok(())
}

fn vanity (substring: &str) {
    extern "C" {
        fn bitcoin_priv2pub (
            ctx: *mut BitcoinCtx, symbol: *const u8, pubkey33: *mut u8, coinaddr: *mut u8,
            privkey: bits256, taddr: u8, addrtype: u8);
    }
    /*
    else if ( argv[1] != 0 && strcmp(argv[1],"vanity") == 0 && argv[2] != 0 )
    */
    let mut pubkey33: [u8; 33] = unsafe {zeroed()};
    let mut coinaddr: [u8; 64] = unsafe {zeroed()};
    let mut wifstr: [c_char; 128] = unsafe {zeroed()};
    let mut privkey: bits256 = unsafe {zeroed()};
    unsafe {lp::LP_mutex_init()};
    let ctx = unsafe {bitcoin_ctx()};
    unsafe {lp::LP_initcoins (ctx as *mut c_void, -1, unwrap! (CJSON::from_str ("[]")) .0)};
    let timestamp = now_ms() / 1000;
    println! ("start vanitygen ({}).{} t.{}", substring, substring.len(), timestamp);
    for i in 0..1000000000 {
        privkey.bytes = random();
        unsafe {bitcoin_priv2pub (ctx, "KMD\0".as_ptr(), pubkey33.as_mut_ptr(), coinaddr.as_mut_ptr(), privkey, 0, 60)};
        let coinaddr = unsafe {from_utf8_unchecked (from_raw_parts (coinaddr.as_ptr(), 34))};
        if &coinaddr[1 .. substring.len()] == &substring[0 .. substring.len() - 1] {  // Print on near match.
            unsafe {bitcoin_priv2wif ("KMD\0".as_ptr(), 0, wifstr.as_mut_ptr(), privkey, 188)};
            let wifstr = unwrap! (unsafe {CStr::from_ptr (wifstr.as_ptr())} .to_str());
            println! ("i.{} {} -> {} wif.{}", i, privkey, coinaddr, wifstr);
            if coinaddr.as_bytes()[substring.len()] == substring.as_bytes()[substring.len() - 1] {break}  // Stop on full match.
        }
    }
    println! ("done vanitygen.({}) done {} elapsed {}\n", substring, now_ms() / 1000, now_ms() / 1000 - timestamp);
}

fn fix_directories() -> bool {
    unsafe {os::OS_ensure_directory (lp::GLOBAL_DBDIR.as_ptr() as *mut c_char)};
    let dbdir = global_dbdir();
    if !ensure_writable (&dbdir.join ("SWAPS")) {return false}
    if !ensure_writable (&dbdir.join ("GTC")) {return false}
    if !ensure_writable (&dbdir.join ("PRICES")) {return false}
    if !ensure_writable (&dbdir.join ("UNSPENTS")) {return false}
    true
}

/// Parses the `first_argument` as JSON and starts LP_main.
fn run_lp_main (conf: &str) -> Result<(), String> {
    let c_conf = match CJSON::from_str (conf) {
        Ok (json) => json,
        Err (err) => return ERR! ("couldnt parse.({}).{}", conf, err)
    };
    let conf: Json = match json::from_str(conf) {
        Ok (json) => json,
        Err (err) => return ERR! ("couldnt parse.({}).{}", conf, err)
    };

    if conf["docker"] == 1 {
        unsafe {lp::DOCKERFLAG = 1}
    } else if conf["docker"].is_string() {
        let ip_port = unwrap! (CString::new (unwrap! (conf["docker"].as_str())));
        unsafe {lp::DOCKERFLAG = os::calc_ipbits (ip_port.as_ptr() as *mut c_char) as u32}
    }

    try_s! (lp_main (c_conf, conf));
    Ok(())
}

#[no_mangle]
pub extern fn log_stacktrace (desc: *const c_char) {
    let desc = if desc == null() {
        ""
    } else {
        match unsafe {CStr::from_ptr (desc)} .to_str() {
            Ok (s) => s,
            Err (err) => {
                eprintln! ("log_stacktrace] Bad trace description: {}", err);
                ""
            }
        }
    };
    let mut trace = String::with_capacity (4096);
    stack_trace (&mut stack_trace_frame, &mut |l| trace.push_str (l));
    eprintln! ("Stacktrace. {}\n{}", desc, trace);
}