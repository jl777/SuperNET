extern crate regex;
extern crate dirs;
use common::for_tests::{MarketMakerIt, RaiiDump, RaiiKill};
use common::log::dashboard_path;
use gstuff::{now_float, slurp};
use hyper::StatusCode;
use hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN;
use libc::c_char;
use serde_json::{self as json, Value as Json};
use std::borrow::Cow;
use std::env::{self, var};
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::{from_utf8_unchecked};
use std::thread::{self, sleep};
use std::time::Duration;

/// Create RAII variables to the effect of dumping the log and the status dashboard at the end of the scope.
pub fn mm_dump (log_path: &Path) -> (RaiiDump, RaiiDump) {(
    RaiiDump {log_path: log_path.to_path_buf()},
    RaiiDump {log_path: unwrap! (dashboard_path (log_path))}
)}

/// A typical MM instance.
fn mm_spat() -> (&'static str, MarketMakerIt, RaiiDump, RaiiDump) {
    let passphrase = "SPATsRps3dhEtXwtnpRCKF";
    let mm = unwrap! (MarketMakerIt::start (
        json! ({
            "gui": "nogui",
            "client": 1,
            "passphrase": passphrase,
            "rpccors": "http://localhost:4000",
            "coins": [
                {"coin": "BEER","asset": "BEER", "rpcport": 8923},
                {"coin": "PIZZA","asset": "PIZZA", "rpcport": 11116}
            ]
        }),
        "aa503e7d7426ba8ce7f6627e066b04bf06004a41fd281e70690b3dbc6e066f69".into(),
        match var ("LOCAL_THREAD_MM") {Ok (ref e) if e == "1" => Some (local_start()), _ => None}
    ));
    let (dump_log, dump_dashboard) = mm_dump (&mm.log_path);
    (passphrase, mm, dump_log, dump_dashboard)
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

/// Asks MM to enable the given currency in native mode.  
/// Returns the RPC reply containing the corresponding wallet address.
fn enable_native(mm: &MarketMakerIt, coin: &str) -> String {
    let native = unwrap! (mm.rpc (json! ({
        "userpass": mm.userpass,
        "method": "enable",
        "coin": coin,
    })));
    assert_eq! (native.0, StatusCode::OK);
    native.1
}

/// Enables BEER, PIZZA, ETOMIC and ETH.
/// Returns the RPC replies containing the corresponding wallet addresses.
fn enable_coins(mm: &MarketMakerIt) -> Vec<(&'static str, String)> {
    let mut replies = Vec::new();
    replies.push (("BEER", enable_native (mm, "BEER")));
    replies.push (("PIZZA", enable_native (mm, "PIZZA")));
    replies.push (("ETOMIC", enable_native(mm, "ETOMIC")));
    replies.push (("ETH", enable_native (mm, "ETH")));
    replies
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

    let (passphrase, mm, _dump_log, _dump_dashboard) = mm_spat();
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
    log! ({"test_autoprice] coinaddr: {}.", unwrap! (address["coinaddr"].as_str(), "!coinaddr")});

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
    let (_, mm, _dump_log, _dump_dashboard) = mm_spat();
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
    log! ({"fundvalue response: {}", unwrap! (json::to_string_pretty (&fundvalue))});

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
    let (_, mm, _dump_log, _dump_dashboard) = mm_spat();
    unwrap! (mm.wait_for_log (19., &|log| log.contains (">>>>>>>>> DEX stats ")));

    let no_method = unwrap! (mm.rpc (json! ({
        "userpass": mm.userpass,
        "coin": "BEER",
        "ipaddr": "electrum1.cipig.net",
        "port": 10022
    })));
    assert! (no_method.0.is_server_error());
    assert_eq!((no_method.2)[ACCESS_CONTROL_ALLOW_ORIGIN], "http://localhost:4000");

    let not_json = unwrap! (mm.rpc_str("It's just a string"));
    assert! (not_json.0.is_server_error());
    assert_eq!((not_json.2)[ACCESS_CONTROL_ALLOW_ORIGIN], "http://localhost:4000");

    let unknown_method = unwrap! (mm.rpc (json! ({
        "method": "unknown_method",
    })));

    assert! (unknown_method.0.is_server_error());
    assert_eq!((unknown_method.2)[ACCESS_CONTROL_ALLOW_ORIGIN], "http://localhost:4000");

    let mpnet = unwrap! (mm.rpc (json! ({
        "userpass": mm.userpass,
        "method": "mpnet",
        "onoff": 1,
    })));
    assert_eq!(mpnet.0, StatusCode::OK);
    assert_eq!((mpnet.2)[ACCESS_CONTROL_ALLOW_ORIGIN], "http://localhost:4000");

    unwrap! (mm.wait_for_log (1., &|log| log.contains ("MPNET onoff")));

    let version = unwrap! (mm.rpc (json! ({
        "userpass": mm.userpass,
        "method": "version",
    })));
    assert_eq!(version.0, StatusCode::OK);
    assert_eq!((version.2)[ACCESS_CONTROL_ALLOW_ORIGIN], "http://localhost:4000");

    let help = unwrap! (mm.rpc (json! ({
        "userpass": mm.userpass,
        "method": "help",
    })));
    assert_eq!(help.0, StatusCode::OK);
    assert_eq!((help.2)[ACCESS_CONTROL_ALLOW_ORIGIN], "http://localhost:4000");

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
    if let Ok (conf) = var ("_MM2_TEST_CONF") {
        log! ("test_mm_start] Starting the MarketMaker...");
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

/// Typically used when the `LOCAL_THREAD_MM` env is set, helping debug the tested MM.
fn local_start_impl (folder: PathBuf, log_path: PathBuf, mut conf: Json) {
    unwrap! (thread::Builder::new().name ("MM".into()) .spawn (move || {
        if conf["log"].is_null() {
            conf["log"] = unwrap! (log_path.to_str()) .into();
        } else {
            let path = Path::new (unwrap! (conf["log"].as_str(), "log is not a string"));
            assert_eq! (log_path, path);
        }

        log! ({"local_start] MM in a thread, log {:?}.", log_path});

        chdir (&folder);

        let c_json = unwrap! (CString::new (unwrap! (json::to_string (&conf))));
        let c_conf = unwrap! (CJSON::from_zero_terminated (c_json.as_ptr() as *const c_char));
        unwrap! (lp_main (c_conf, conf))
    }));
}

fn local_start() -> fn (PathBuf, PathBuf, Json) {local_start_impl}

/// Integration test for the "mm2 events" mode.
/// Starts MM in background and verifies that "mm2 events" produces a non-empty feed of events.
#[test]
fn test_events() {
    let executable = unwrap! (env::args().next());
    let executable = unwrap! (Path::new (&executable) .canonicalize());
    let mm_events_output = env::temp_dir().join ("test_events.mm_events.log");
    match var ("_MM2_TEST_EVENTS_MODE") {
        Ok (ref mode) if mode == "MM_EVENTS" => {
            log! ("test_events] Starting the `mm2 events`...");
            unwrap! (events (&["_test".into(), "events".into()]));
        },
        _ => {
            let mut mm = unwrap! (MarketMakerIt::start (
                json! ({"gui": "nogui", "client": 1, "passphrase": "123", "coins": "BTC,KMD"}),
                "5bfaeae675f043461416861c3558146bf7623526891d890dc96bc5e0e5dbc337".into(),
                match var ("LOCAL_THREAD_MM") {Ok (ref e) if e == "1" => Some (local_start()), _ => None}));
            let (_dump_log, _dump_dashboard) = mm_dump (&mm.log_path);

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
                        let (status, body, _headers) = unwrap! (mm.rpc (json! (
                            {"userpass": mm.userpass, "method": "getendpoint"})));
                        log! ({"test_events] getendpoint response: {:?}, {}", status, body});
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

/// Invokes the RPC "notify" method, adding a node to the peer-to-peer ring.
#[test]
fn test_notify() {
    let (_passphrase, mm, _dump_log, _dump_dashboard) = mm_spat();
    unwrap! (mm.wait_for_log (19., &|log| log.contains (">>>>>>>>> DEX stats ")));

    let notify = unwrap! (mm.rpc (json! ({
        "method": "notify",
        "rmd160": "9562c4033b6ac1ea2378636a782ce5fdf7ee9a2d",
        "pub": "5eb48483573d44f1b24e33414273384c2f0ae15ecab7f700fb3042f904b09820",
        "pubsecp": "0342407c81e408d9d6cdec35576d7284b712ee4062cb908574b5bc6bb46406f8ad",
        "timestamp": 1541434098,
        "sig":  "1f1e2198d890eeb2fc0004d092ff1266c1be10ca16a0cbe169652c2dc1b3150e5918fd9c7fc5161a8f05f4384eb05fc92e4e9c1abb551795f447b0433954f29990",
        "isLP": "45.32.19.196",
        "session": 1540419658,
    })));
    assert_eq! (notify.0, StatusCode::OK, "notify reply: {:?}", notify);
    unwrap! (mm.wait_for_log (9., &|log| log.contains ("lp_notify_recv] hailed by peer: 45.32.19.196")));
}

// Running subcrate unit tests is often suboptimal because we have to build
// a separate test binary and link all the C libraries there,
// which slows us both when we run the tests and when we maintain them.
// So instead of running the `common` unit tests from a separate binary I'm simply proxying them here.
// Let's see how this approach will fare (PDIA: positive practices scale through diffusion).
#[test]
fn test_status() {common::log::test::test_status()}

#[cfg(windows)]
fn get_special_folder_path() -> PathBuf {
    use std::ffi::CStr;
    use std::mem::zeroed;
    use std::ptr::null_mut;
    use winapi::um::shlobj::SHGetSpecialFolderPathA;
    use winapi::shared::minwindef::MAX_PATH;
    use winapi::um::shlobj::CSIDL_APPDATA;

    let mut buf: [c_char; MAX_PATH + 1] = unsafe {zeroed()};
    // https://docs.microsoft.com/en-us/windows/desktop/api/shlobj_core/nf-shlobj_core-shgetspecialfolderpatha
    let rc = unsafe {SHGetSpecialFolderPathA (null_mut(), buf.as_mut_ptr(), CSIDL_APPDATA, 1)};
    if rc != 1 {panic! ("!SHGetSpecialFolderPathA")}
    Path::new (unwrap! (unsafe {CStr::from_ptr (buf.as_ptr())} .to_str())) .to_path_buf()
}

#[cfg(not(windows))]
fn get_special_folder_path() -> PathBuf {panic!("!windows")}

/// Determines komodod conf file location, emulating komodo/util.cpp/GetConfigFile.
fn komodo_conf_path (ac_name: Option<&'static str>) -> Result<PathBuf, String> {
    let confname: Cow<str> = if let Some (ac_name) = ac_name {
        format! ("{}.conf", ac_name).into()
    } else {
        "komodo.conf".into()
    };

    // komodo/util.cpp/GetDefaultDataDir

    let mut path = match dirs::home_dir() {
        Some (hd) => hd,
        None => Path::new ("/") .to_path_buf()
    };

    if cfg! (windows) {
        // >= Vista: c:\Users\$username\AppData\Roaming
        path = get_special_folder_path();
        path.push ("Komodo");
    } else if cfg! (target_os = "macos") {
        path.push ("Library");
        path.push ("Application Support");
        path.push ("Komodo");
    } else {
        path.push (".komodo");
    }

    if let Some (ac_name) = ac_name {path.push (ac_name)}
    Ok (path.join (&confname[..]))
}

fn trade_base_rel(base: &str, rel: &str) {
    // Keep BEER here for some time as coin maybe will be back
    let beer_cfp = unwrap! (komodo_conf_path (Some ("BEER")));
    let pizza_cfp = unwrap! (komodo_conf_path (Some ("PIZZA")));
    let etomic_cfp = unwrap! (komodo_conf_path (Some ("ETOMIC")));
    assert! (beer_cfp.exists(), "BEER config {:?} is not found", beer_cfp);
    assert! (pizza_cfp.exists(), "PIZZA config {:?} is not found", pizza_cfp);
    assert! (etomic_cfp.exists(), "ETOMIC config {:?} is not found", etomic_cfp);

    fn from_env_file (env: Vec<u8>) -> (Option<String>, Option<String>) {
        use mm2_tests::regex::bytes::Regex;
        let (mut passphrase, mut userpass) = (None, None);
        for cap in unwrap! (Regex::new (r"(?m)^(PASSPHRASE|USERPASS)=(\w[\w ]+)$")) .captures_iter (&env) {
            match cap.get (1) {
                Some (name) if name.as_bytes() == b"PASSPHRASE" =>
                    passphrase = cap.get (2) .map (|v| unwrap! (String::from_utf8 (v.as_bytes().into()))),
                Some (name) if name.as_bytes() == b"USERPASS" =>
                    userpass = cap.get (2) .map (|v| unwrap! (String::from_utf8 (v.as_bytes().into()))),
                _ => ()
            }
        }
        (passphrase, userpass)
    }
    let (bob_file_passphrase, bob_file_userpass) = from_env_file (slurp (&".env.seed"));
    let (alice_file_passphrase, alice_file_userpass) = from_env_file (slurp (&".env.client"));

    let bob_passphrase = unwrap! (var ("BOB_PASSPHRASE") .ok().or (bob_file_passphrase), "No BOB_PASSPHRASE or .env.seed/PASSPHRASE");
    let bob_userpass = unwrap! (var ("BOB_USERPASS") .ok().or (bob_file_userpass), "No BOB_USERPASS or .env.seed/USERPASS");
    let alice_passphrase = unwrap! (var ("ALICE_PASSPHRASE") .ok().or (alice_file_passphrase), "No ALICE_PASSPHRASE or .env.client/PASSPHRASE");
    let alice_userpass = unwrap! (var ("ALICE_USERPASS") .ok().or (alice_file_userpass), "No ALICE_USERPASS or .env.client/USERPASS");

    let coins = json!([
        {"coin":"BEER","asset":"BEER","rpcport":8923,"confpath":unwrap!(beer_cfp.to_str())},
        {"coin":"PIZZA","asset":"PIZZA","rpcport":11608,"confpath":unwrap!(pizza_cfp.to_str())},
        {"coin":"ETOMIC","asset":"ETOMIC","rpcport":10271,"confpath":unwrap!(etomic_cfp.to_str())},
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
        match var ("LOCAL_THREAD_MM") {Ok (ref e) if e == "bob" => Some (local_start()), _ => None}
    ));

    let mm_alice = unwrap! (MarketMakerIt::start (
        json! ({
            "gui": "nogui",
            "netid": 9999,
            "passphrase": alice_passphrase,
            "coins": coins,
            "seednode": fomat!((mm_bob.ip)),
            "client": 1,
            "alice_contract":"0xe1d4236c5774d35dc47dcc2e5e0ccfc463a3289c",
            "bob_contract":"0x105aFE60fDC8B5c021092b09E8a042135A4A976E",
            "ethnode":"http://195.201.0.6:8545"
        }),
        alice_userpass,
        match var ("LOCAL_THREAD_MM") {Ok (ref e) if e == "alice" => Some (local_start()), _ => None}
    ));

    let (_bob_dump_log, _bob_dump_dashboard) = mm_dump (&mm_bob.log_path);
    let (_alice_dump_log, _alice_dump_dashboard) = mm_dump (&mm_alice.log_path);
    log!({"Bob log path: {}", mm_bob.log_path.display()});
    log!({"Alice log path: {}", mm_alice.log_path.display()});

    // wait until both nodes RPC API is active
    unwrap! (mm_bob.wait_for_log (22., &|log| log.contains (">>>>>>>>> DEX stats ")));
    unwrap! (mm_alice.wait_for_log (22., &|log| log.contains (">>>>>>>>> DEX stats ")));

    // Enable coins on Bob side. Print the replies in case we need the "smartaddress".
    log! ({"enable_coins (bob): {:?}", enable_coins (&mm_bob)});
    // Enable coins on Alice side. Print the replies in case we need the "smartaddress".
    log! ({"enable_coins (alice): {:?}", enable_coins (&mm_alice)});

    // wait until Alice recognize Bob node by importing it's pubkey
    unwrap! (mm_alice.wait_for_log (33., &|log| log.contains ("set pubkey for")));

    // issue sell request on Bob side by setting PIZZA/ETH price
    log!("Issue bob sell request");
    let rc = unwrap! (mm_bob.rpc (json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": base,
        "rel": rel,
        "price": 0.9
    })));
    assert! (rc.0.is_success(), "!setprice: {}", rc.1);

    // issue PIZZA/ETH buy request from Alice side
    thread::sleep(Duration::from_secs(2));
    log!("Issue alice buy request");
    let rc = unwrap! (mm_alice.rpc (json! ({
        "userpass": mm_alice.userpass,
        "method": "buy",
        "base": base,
        "rel": rel,
        "relvolume": 0.1,  // Should be close enough to the existing UTXOs.
        "price": 1
    })));
    assert! (rc.0.is_success(), "!buy: {}", rc.1);

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

/// Integration test for PIZZA/ETH and ETH/PIZZA trade
/// This test is ignored because as of now it requires additional environment setup:
/// PIZZA and ETOMIC daemons must be running and fully synced for swaps to be successful
/// The trades can't be executed concurrently now for 2 reasons:
/// 1. Bob node starts listening 47772 port on all interfaces so no more Bobs can be started at once
/// 2. Current UTXO handling algo might result to conflicts between concurrently running nodes
/// 
/// Steps that are currently necessary to run this test:
/// 
/// Obtain the wallet binaries (komodod, komodo-cli) from the [Agama wallet](https://github.com/KomodoPlatform/Agama/releases/).
/// (Or use the Docker image artempikulin/komodod-etomic).
/// (Or compile them from [source](https://github.com/jl777/komodo/tree/dev))
/// 
/// Obtain ~/.zcash-params (c:/Users/$username/AppData/Roaming/ZcashParams on Windows).
/// 
/// Start the wallets
/// 
///     komodod -ac_name=PIZZA -ac_supply=100000000 -addnode=24.54.206.138 -addnode=78.47.196.146
/// 
/// and
/// 
///     komodod -ac_name=ETOMIC -ac_supply=100000000 -addnode=78.47.196.146
/// 
/// and (if you want to test BEER coin):
///
///     komodod -ac_name=BEER -ac_supply=100000000 -addnode=78.47.196.146 -addnode=43.245.162.106 -addnode=88.99.153.2 -addnode=94.130.173.120 -addnode=195.201.12.150 -addnode=23.152.0.28
///
/// Get rpcuser and rpcpassword from ETOMIC/ETOMIC.conf
/// (c:/Users/$username/AppData/Roaming/Komodo/ETOMIC/ETOMIC.conf on Windows)
/// and run
/// 
///     komodo-cli -ac_name=ETOMIC importaddress RKGn1jkeS7VNLfwY74esW7a8JFfLNj1Yoo
/// 
/// Share the wallet information with the test. On Windows:
/// 
///     set BOB_PASSPHRASE=...
///     set BOB_USERPASS=...
///     set ALICE_PASSPHRASE=...
///     set ALICE_USERPASS=...
/// 
/// And run the test:
/// 
///     cargo test trade -- --nocapture --ignored
#[test]
#[ignore]
fn test_trade() {
    trade_base_rel("PIZZA", "ETH");
    trade_base_rel("ETH", "PIZZA");
}
