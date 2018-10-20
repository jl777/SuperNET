extern crate dirs;
use common::for_tests::{MarketMakerIt, RaiiDump, RaiiKill};
use common::log::dashboard_path;
use gstuff::{now_float, slurp};
use hyper::StatusCode;
use libc::c_char;
use serde_json::{self as json, Value as Json};
use std::env;
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::{from_utf8_unchecked};
use std::thread::{self, sleep};
use std::time::Duration;

fn mm_spat() -> (&'static str, MarketMakerIt) {
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
    (passphrase, mm)
}

/// Asks MM to enable the given currency in electrum mode
/// fresh list of servers at https://github.com/jl777/coins/blob/master/electrums/.
fn enable_electrum(mm: &MarketMakerIt, coin: &str, ipaddr: &str, port: i32) {
    let electrum = unwrap! (mm.rpc (json! ({
        "userpass": mm.userpass,
        "method": "electrum",
        "coin": coin,
        "ipaddr": ipaddr,
        "port": port
    })));
    assert_eq! (electrum.0, StatusCode::OK);
}

/// Asks MM to enable the given currency in native mode
fn enable_native(mm: &MarketMakerIt, coin: &str) {
    let native = unwrap! (mm.rpc (json! ({
        "userpass": mm.userpass,
        "method": "enable",
        "coin": coin,
    })));
    assert_eq! (native.0, StatusCode::OK);
}

/// Helper function enabling required coins
fn enable_coins(mm: &MarketMakerIt) {
    enable_native(mm, "BEER");
    enable_native(mm, "ETOMIC");
    enable_native(mm, "ETH");
}

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

    let (passphrase, mm) = mm_spat();
    let _dump_log = RaiiDump {log_path: mm.log_path.clone()};
    let _dump_dashboard = RaiiDump {log_path: unwrap! (dashboard_path (&mm.log_path))};
    unwrap! (mm.wait_for_log (19., &|log| log.contains (">>>>>>>>> DEX stats ")));

    enable_electrum(&mm, "BEER", "electrum1.cipig.net", 10022);
    enable_electrum(&mm, "PIZZA", "electrum1.cipig.net", 10024);

    // Looks like we don't need enabling the coin to base the price on it.
    // let electrum_dash = unwrap! (mm.rpc (json! ({
    //     "userpass": mm.userpass,
    //     "method": "electrum",
    //     "coin": "DASH",
    //     "ipaddr": "electrum1.cipig.net",
    //     "port": 10061
    // })));
    // assert_eq! (electrum_dash.0, StatusCode::OK);

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
        "margin": 0.5,
        // We're basing the price of our order on the price of DASH, triggering the extra price fetch in `lp_autoprice_iter`.
        "refbase": "dash",
        "refrel": "coinmarketcap"
    })));
    assert_eq! (autoprice.0, StatusCode::OK, "autoprice reply: {:?}", autoprice);

    // TODO: Turn into a proper (human-readable, tagged) log entry?
    unwrap! (mm.wait_for_log (9., &|log| log.contains ("lp_autoprice] 0 Using ref dash/coinmarketcap for PIZZA/BEER factor None")));

    unwrap! (mm.wait_for_log (44., &|log| log.contains ("Waiting for Bittrex market summaries... Ok.")));
    unwrap! (mm.wait_for_log (44., &|log| log.contains ("Waiting for Cryptopia markets... Ok.")));
    unwrap! (mm.wait_for_log (44., &|log| log.contains ("Waiting for coin prices (KMD, BCH, LTC)... Done!")));
    unwrap! (mm.wait_for_log (9., &|log| {
        log.contains ("[portfolio ext-price ref-num=0] Discovered the Bitcoin price of dash is 0.") ||
        log.contains ("[portfolio ext-price ref-num=0] Waiting for the CoinGecko Bitcoin price of dash ... Done")
    }));

    // Checking the autopricing logs here TDD-helps us with the porting effort.
    //
    // The logging format is in flux until we start exporting the logs to websocket using them from HyperDEX.
    // And the stdout format can be changed even after that.

    unwrap! (mm.stop());

    // See if `LogState` is properly dropped, which is needed in order to log the remaining dashboard entries.
    unwrap! (mm.wait_for_log (9., &|log| log.contains ("rpc] on_stop, firing shutdown_tx!")));
    unwrap! (mm.wait_for_log (9., &|log| log.contains ("LogState] Bye!") || log.contains ("--- LogState] Remaining status entries. ---")));
}

#[test]
fn test_fundvalue() {
    let (_, mm) = mm_spat();
    let _dump_log = RaiiDump {log_path: mm.log_path.clone()};
    let _dump_dashboard = RaiiDump {log_path: unwrap! (dashboard_path (&mm.log_path))};
    unwrap! (mm.wait_for_log (19., &|log| log.contains (">>>>>>>>> DEX stats ")));

    let fundvalue = unwrap! (mm.rpc (json! ({
        "userpass": mm.userpass,
        "method": "fundvalue",
        "address": "RFf5mf3AoixXzmNLAmgs2L5eWGveSo6X7q",  // We have some BEER and PIZZA here.
        "holdings": [
            // Triggers the `LP_KMDvalue` code path and touches the `KMDholdings`.
            {"coin": "KMD", "balance": 123},
            // Triggers the `LP_CMCbtcprice` code path.
            {"coin": "litecoin", "balance": 123},
            // No such coin, should trigger the "no price source" part in the response.
            {"coin": "- bogus coin -", "balance": 123}
        ]
    })));
    assert! (fundvalue.0.is_success(), "{:?}", fundvalue);
    let fundvalue: Json = unwrap! (json::from_str (&fundvalue.1));
    println! ("fundvalue response: {}", unwrap! (json::to_string_pretty (&fundvalue)));

    // NB: Ideally we'd have `LP_balances` find the BEER and PIZZA balances we have on the "address",
    // but as of now I don't see a simple way to trigger the "importaddress" and "rescan" that seems necessary for that.

    assert! (!fundvalue["KMD_BTC"].is_null());
    assert_eq! (fundvalue["KMDholdings"].as_f64(), Some (123.));
    assert! (!fundvalue["btc2kmd"].is_null());
    assert! (!fundvalue["btcsum"].is_null());
    assert! (!fundvalue["fundvalue"].is_null());

    assert_eq! (fundvalue["holdings"][0]["coin"].as_str(), Some ("KMD"));
    assert_eq! (fundvalue["holdings"][0]["KMD"].as_f64(), Some (123.));

    assert_eq! (fundvalue["holdings"][1]["coin"].as_str(), Some ("litecoin"));
    assert_eq! (fundvalue["holdings"][1]["balance"].as_f64(), Some (123.));

    assert_eq! (fundvalue["holdings"][2]["coin"].as_str(), Some ("- bogus coin -"));
    assert_eq! (fundvalue["holdings"][2]["error"].as_str(), Some ("no price source"));

    unwrap! (mm.wait_for_log (1., &|log|
        log.contains ("lp_fundvalue] LP_KMDvalue of 'KMD' is 12300000000") &&
        log.contains ("[portfolio fundvalue ext-prices] Waiting for prices (litecoin,- bogus coin -,komodo) ... 2 out of 3 obtained")
    ));
}

/// Integration test for RPC server.
/// Check that MM doesn't crash in case of invalid RPC requests
#[test]
fn test_rpc() {
    let (_, mm) = mm_spat();
    let _dump_log = RaiiDump {log_path: mm.log_path.clone()};
    unwrap! (mm.wait_for_log (19., &|log| log.contains (">>>>>>>>> DEX stats ")));

    let no_method = unwrap! (mm.rpc (json! ({
        "userpass": mm.userpass,
        "coin": "BEER",
        "ipaddr": "electrum1.cipig.net",
        "port": 10022
    })));
    assert! (no_method.0.is_client_error());

    let not_json = unwrap! (mm.rpc_str("It's just a string"));
    assert! (not_json.0.is_server_error());

    let unknown_method = unwrap! (mm.rpc (json! ({
        "method": "unknown_method",
    })));

    assert! (unknown_method.0.is_server_error());

    let mpnet = unwrap! (mm.rpc (json! ({
        "userpass": mm.userpass,
        "method": "mpnet",
        "onoff": 1,
    })));
    assert_eq!(mpnet.0, StatusCode::OK);
    unwrap! (mm.wait_for_log (1., &|log| log.contains ("MPNET onoff")));

    let version = unwrap! (mm.rpc (json! ({
        "userpass": mm.userpass,
        "method": "version",
    })));
    assert_eq!(version.0, StatusCode::OK);

    let help = unwrap! (mm.rpc (json! ({
        "userpass": mm.userpass,
        "method": "help",
    })));
    assert_eq!(help.0, StatusCode::OK);

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
            let _dump_log = RaiiDump {log_path: mm.log_path.clone()};

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

                if now_float() - started > 60. {panic! ("Test didn't pass withing the 60 seconds timeframe. mm_state={:?}", mm_state)}
                sleep (Duration::from_millis (20))
            }
        }
    }
}

fn trade_base_rel(base: &str, rel: &str) {
    let home_dir = unwrap!(dirs::home_dir());
    let mut beer_path = home_dir.clone();;
    let mut etomic_path = home_dir.clone();
    beer_path.push(".komodo/BEER/BEER.conf");
    etomic_path.push(".komodo/ETOMIC/ETOMIC.conf");
    assert!(beer_path.exists(), "BEER config is not found");
    assert!(etomic_path.exists(), "ETOMIC config is not found");

    let bob_passphrase = unwrap!(env::var("BOB_PASSPHRASE"));
    let bob_userpass = unwrap!(env::var("BOB_USERPASS"));
    let alice_passphrase = unwrap!(env::var("ALICE_PASSPHRASE"));
    let alice_userpass = unwrap!(env::var("ALICE_USERPASS"));

    let coins = json!([
                    {"coin":"BEER","asset":"BEER","rpcport":8923,"confpath":beer_path.to_str().unwrap()},
                    {"coin":"ETOMIC","asset":"ETOMIC","rpcport":10271,"confpath":etomic_path.to_str().unwrap()},
                    {"coin":"ETH","name":"ethereum","etomic":"0x0000000000000000000000000000000000000000","rpcport":80}
                ]);

    let mm_bob = unwrap! (MarketMakerIt::start (
                json! ({
                    "gui": "nogui",
                    "netid": 9999,
                    "passphrase": bob_passphrase,
                    "coins": coins,
                    "alice_contract":"0xe1d4236c5774d35dc47dcc2e5e0ccfc463a3289c",
                    "bob_contract":"0x105aFE60fDC8B5c021092b09E8a042135A4A976E",
                    "ethnode":"http://195.201.0.6:8545"
                }),
                bob_userpass,
                local_start
            ));

    let mm_alice = unwrap! (MarketMakerIt::start (
                json! ({
                    "gui": "nogui",
                    "netid": 9999,
                    "passphrase": alice_passphrase,
                    "coins": coins,
                    "seednode": format!("{}", mm_bob.ip),
                    "client": 1,
                    "alice_contract":"0xe1d4236c5774d35dc47dcc2e5e0ccfc463a3289c",
                    "bob_contract":"0x105aFE60fDC8B5c021092b09E8a042135A4A976E",
                    "ethnode":"http://195.201.0.6:8545"
                }),
                alice_userpass,
                local_start
            ));

    let _bob_dump_log = RaiiDump {log_path: mm_bob.log_path.clone()};
    let _alice_dump_log = RaiiDump {log_path: mm_alice.log_path.clone()};
    println!("Bob log path: {}", mm_bob.log_path.display());
    println!("Alice log path: {}", mm_alice.log_path.display());

    // wait until both nodes RPC API is active
    unwrap! (mm_bob.wait_for_log (5., &|log| log.contains (">>>>>>>>> DEX stats ")));
    unwrap! (mm_alice.wait_for_log (5., &|log| log.contains (">>>>>>>>> DEX stats ")));

    // enable coins on Bob side
    enable_coins(&mm_bob);
    // enable coins on Alice side
    enable_coins(&mm_alice);

    // wait until Alice recognize Bob node by importing it's pubkey
    unwrap! (mm_alice.wait_for_log (20., &|log| log.contains ("set pubkey for")));

    // issue sell request on Bob side by setting BEER/ETH price
    println!("Issue bob sell request");
    unwrap! (mm_bob.rpc (json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": base,
        "rel": rel,
        "price": 0.9
    })));
    // issue BEER/ETH buy request from Alice side
    thread::sleep(Duration::from_secs(2));
    println!("Issue alice buy request");
    unwrap! (mm_alice.rpc (json! ({
        "userpass": mm_alice.userpass,
        "method": "buy",
        "base": base,
        "rel": rel,
        "relvolume": 0.01,
        "price": 1
    })));

    // ensure the swap started
    unwrap! (mm_alice.wait_for_log (20., &|log| log.contains ("start swap iamalice")));
    unwrap! (mm_bob.wait_for_log (20., &|log| log.contains ("start swap iambob")));

    // wait for swap to complete on both sides
    unwrap! (mm_alice.wait_for_log (600., &|log| log.contains ("SWAP completed")));
    unwrap! (mm_bob.wait_for_log (600., &|log| log.contains ("SWAP completed")));

    // check that swap ended successfully
    unwrap! (mm_alice.wait_for_log (5., &|log| log.contains (r#""result":"success","status":"finished""#)));
    unwrap! (mm_bob.wait_for_log (5., &|log| log.contains (r#""result":"success","status":"finished""#)));

    unwrap! (mm_bob.stop());
    unwrap! (mm_alice.stop());
}

/// Integration test for BEER/ETH and ETH/BEER trade
/// This test is ignored because it requires additional environment setup:
/// BEER and ETOMIC daemons must be running and fully synced for swaps to be successful
/// The trades can't be executed concurrently now for 2 reasons:
/// 1. Bob node starts listening 47772 port on all interfaces so no more Bobs can be started at once
/// 2. Current UTXO handling algo might result to conflicts between concurrently running nodes
#[test]
#[ignore]
fn test_trade() {
    trade_base_rel("BEER", "ETH");
    trade_base_rel("ETH", "BEER");
}
