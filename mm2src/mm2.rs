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

extern crate backtrace;

#[allow(unused_imports)]
#[macro_use]
extern crate duct;

#[cfg(feature = "etomic")]
extern crate etomiclibrs;

#[macro_use]
extern crate fomat_macros;

extern crate futures;
extern crate futures_cpupool;

#[macro_use]
extern crate gstuff;

extern crate hyper;

#[allow(unused_imports)]
#[macro_use]
extern crate lazy_static;

extern crate libc;

extern crate nix;

#[macro_use]
extern crate unwrap;

extern crate winapi;

// Re-export preserves the functions that are temporarily accessed from C during the gradual port.
#[cfg(feature = "etomic")]
pub use etomiclibrs::*;

use std::env;
use std::ffi::{CStr, OsString};
use std::fmt;
use std::io::{self, Write};
use std::os::raw::{c_char, c_int, c_void};
use std::mem::zeroed;
use std::ptr::{null, null_mut};
use std::sync::Mutex;

pub mod crash_reports;
mod curve25519 {include! ("c_headers/curve25519.rs");}
use curve25519::{_bits256 as bits256};
enum cJSON {}
#[allow(dead_code)]
extern "C" {
    fn bits256_str (hexstr: *mut u8, x: bits256) -> *const c_char;
    /// NB: Use RAII CJSON instead.
    fn cJSON_Parse (json: *const u8) -> *mut cJSON;
    /// Defined when cJSON_Parse() returns 0. 0 when cJSON_Parse() succeeds.
    fn cJSON_GetErrorPtr() -> *const c_char;
    fn cJSON_Delete (c_json: *mut cJSON);
    fn LP_main (c_json: *mut cJSON) -> !;
    fn mm1_main (argc: c_int, argv: *const *const c_char) -> !;
}

use crash_reports::init_crash_reports;

impl fmt::Display for bits256 {
    fn fmt (&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf: [u8; 65] = unsafe {zeroed()};
        let cs = unsafe {bits256_str (buf.as_mut_ptr(), *self)};
        let hex = unwrap! (unsafe {CStr::from_ptr (cs)} .to_str());
        f.write_str (hex)
    }
}

/// RAII and MT wrapper for `cJSON`.
#[allow(dead_code)]
struct CJSON (*mut cJSON);
#[allow(dead_code)]
impl CJSON {
    fn from_zero_terminated (json: *const u8) -> Result<CJSON, String> {
        lazy_static! {static ref LOCK: Mutex<()> = Mutex::new(());}
        let _lock = try_s! (LOCK.lock());  // Probably need a lock to access the error singleton.
        let c_json = unsafe {cJSON_Parse (json)};
        if c_json == null_mut() {
            let err = unsafe {cJSON_GetErrorPtr()};
            let err = try_s! (unsafe {CStr::from_ptr (err)} .to_str());
            ERR! ("Can't parse JSON, error: {}", err)
        } else {
            Ok (CJSON (c_json))
        }
    }
}
impl Drop for CJSON {
    fn drop (&mut self) {
        unsafe {cJSON_Delete (self.0)}
        self.0 = null_mut()
    }
}

/* The original C code will be replaced with the corresponding Rust code in small increments,
   allowing Git history to catch up and show the function-level diffs.

void PNACL_message(char *arg,...)
{
    
}
#define FROM_MARKETMAKER

#include <stdio.h>
#include <stdint.h>
// #include "lib.h"
#ifndef NATIVE_WINDOWS
#include "OS_portable.h"
#else
*/

#[allow(dead_code,non_upper_case_globals,non_camel_case_types,non_snake_case)]
mod os_portable {include! ("c_headers/OS_portable.rs");}

/*
#endif // !_WIN_32

uint32_t DOCKERFLAG;
#define MAX(a,b) ((a) > (b) ? (a) : (b))
char *stats_JSON(void *ctx,int32_t fastflag,char *myipaddr,int32_t pubsock,cJSON *argjson,char *remoteaddr,uint16_t port);
#include "stats.c"
void LP_priceupdate(char *base,char *rel,double price,double avebid,double aveask,double highbid,double lowask,double PAXPRICES[32]);

*/
#[allow(dead_code,non_upper_case_globals,non_camel_case_types,non_snake_case)]
mod nn {include! ("c_headers/nn.rs");}
/*
#ifndef NN_WS_MSG_TYPE
#define NN_WS_MSG_TYPE 1
#endif


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

void LP_main(void *ptr)
{
    char *passphrase; double profitmargin; uint16_t netid=0,port,pullport,pubport,busport; cJSON *argjson = ptr;
    if ( (passphrase= jstr(argjson,"passphrase")) != 0 )
    {
        profitmargin = jdouble(argjson,"profitmargin");
        LP_profitratio += profitmargin;
        if ( (port= juint(argjson,"rpcport")) < 1000 )
            port = LP_RPCPORT;
        if ( jobj(argjson,"netid") != 0 )
            netid = juint(argjson,"netid");
        LP_ports(&pullport,&pubport,&busport,netid);
        LPinit(port,pullport,pubport,busport,passphrase,jint(argjson,"client"),jstr(argjson,"userhome"),argjson);
    }
}

int32_t ensure_writable(char *dirname)
{
    char fname[512],str[65],str2[65]; bits256 r,check; FILE *fp;
    OS_randombytes(r.bytes,sizeof(r));
    sprintf(fname,"%s/checkval",dirname), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"wb")) == 0 )
    {
        printf("FATAL ERROR cant create %s\n",fname);
        fprintf(stderr,"FATAL ERROR cant create %s\n",fname);
        return(-1);
    }
    else if ( fwrite(r.bytes,1,sizeof(r),fp) != sizeof(r) )
    {
        printf("FATAL ERROR error writing %s\n",fname);
        fprintf(stderr,"FATAL ERROR writing %s\n",fname);
        return(-1);
    }
    else
    {
        fclose(fp);
        if ( (fp= fopen(fname,"rb")) == 0 )
        {
            printf("FATAL ERROR cant open %s\n",fname);
            fprintf(stderr,"FATAL ERROR cant open %s\n",fname);
            return(-1);
        }
        else if ( fread(check.bytes,1,sizeof(check),fp) != sizeof(check) )
        {
            printf("FATAL ERROR error reading %s\n",fname);
            fprintf(stderr,"FATAL ERROR reading %s\n",fname);
            return(-1);
        }
        else if ( memcmp(check.bytes,r.bytes,sizeof(r)) != 0 )
        {
            printf("FATAL ERROR error comparint %s %s vs %s\n",fname,bits256_str(str,r),bits256_str(str2,check));
            fprintf(stderr,"FATAL ERROR error comparint %s %s vs %s\n",fname,bits256_str(str,r),bits256_str(str2,check));
            return(-1);
        }
        fclose(fp);
    }
    return(0);
}

*/

#[cfg(test)]
mod test {
    use duct::Handle;

    use futures::Future;
    use futures_cpupool::CpuPool;

    use gstuff::{now_float, slurp};

    use hyper::{Body, Client, Request, StatusCode};
    use hyper::rt::Stream;

    use std::env;
    use std::fs;
    use std::str::{from_utf8, from_utf8_unchecked};
    use std::thread::sleep;
    use std::time::Duration;

    use super::{btc2kmd, events, LP_main, CJSON};

    /// Automatically kill a wrapped process.
    struct RaiiKill {handle: Handle, running: bool}
    impl RaiiKill {
        fn from_handle (handle: Handle) -> RaiiKill {
            RaiiKill {handle, running: true}
        }
        fn running (&mut self) -> bool {
            if !self.running {return false}
            match self.handle.try_wait() {Ok (None) => true, _ => {self.running = false; false}}
        }
    }
    impl Drop for RaiiKill {
        fn drop (&mut self) {
            // The cached `running` check might provide some protection against killing a wrong process under the same PID,
            // especially if the cached `running` check is also used to monitor the status of the process.
            if self.running() {
                let _ = self.handle.kill();
            }
        }
    }

    /// Integration (?) test for the "btc2kmd" command line invocation.
    /// The argument is the WIF example from https://en.bitcoin.it/wiki/Wallet_import_format.
    #[test]
    fn test_btc2kmd() {
        let output = unwrap! (btc2kmd ("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"));
        assert_eq! (output, "BTC 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ \
        -> KMD UpRBUQtkA5WqFnSztd7sCYyyhtd4aq6AggQ9sXFh2fXeSnLHtd3Z: \
        privkey 0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
    }

    /// Integration test for the "mm2 events" mode.
    /// Starts MM in background and verifies that "mm2 events" produces a non-empty feed of events.
    #[test]
    fn test_events() {
        let executable = unwrap! (env::args().next());
        let mm_output = env::temp_dir().join ("test_events.mm.log");
        let mm_events_output = env::temp_dir().join ("test_events.mm_events.log");
        match env::var ("MM2_TEST_EVENTS_MODE") {
            Ok (ref mode) if mode == "MM" => {
                println! ("test_events] Starting the MarketMaker...");
                let c_json = unwrap! (CJSON::from_zero_terminated ("{\
                \"gui\":\"nogui\",\
                \"unbuffered-output\":1,\
                \"client\":1,\
                \"passphrase\":\"123\",\
                \"coins\":\"BTC,KMD\"\
                }\0".as_ptr()));
                unsafe {LP_main (c_json.0)}
            },
            Ok (ref mode) if mode == "MM_EVENTS" => {
                println! ("test_events] Starting the `mm2 events`...");
                unwrap! (events (&["_test".into(), "events".into()]));
            },
            _ => {
                // Start the MM.
                println! ("test_events] executable: '{}'.", executable);
                println! ("test_events] `mm2` log: {:?}.", mm_output);
                println! ("test_events] `mm2 events` log: {:?}.", mm_events_output);
                let mut mm = RaiiKill::from_handle (unwrap! (cmd! (&executable, "test_events", "--nocapture")
                    .env ("MM2_TEST_EVENTS_MODE", "MM")
                    .env ("MM2_UNBUFFERED_OUTPUT", "1")
                    .stderr_to_stdout().stdout (&mm_output) .start()));

                let mut mm_events = RaiiKill::from_handle (unwrap! (cmd! (executable, "test_events", "--nocapture")
                    .env ("MM2_TEST_EVENTS_MODE", "MM_EVENTS")
                    .env ("MM2_UNBUFFERED_OUTPUT", "1")
                    .stderr_to_stdout().stdout (&mm_events_output) .start()));

                #[derive(Debug)] enum MmState {Starting, Started, GetendpointSent, Passed}
                let mut mm_state = MmState::Starting;

                // Monitor the MM output.
                let started = now_float();
                loop {
                    if !mm.running() {panic! ("MM process terminated prematurely.")}
                    if !mm_events.running() {panic! ("`mm2 events` terminated prematurely.")}

                    /// Invokes a locally running MM and returns it's reply.
                    fn call_mm (json: String) -> Result<(StatusCode, String), String> {
                        let pool = CpuPool::new (1);
                        let client = Client::builder().executor (pool.clone()) .build_http::<Body>();
                        let fut = pool.spawn (client.request (try_s! (
                            Request::builder().method ("POST") .uri ("http://127.0.0.1:7783") .body (json.into()))));
                        let res = try_s! (fut.wait());
                        let status = res.status();
                        let body = try_s! (pool.spawn (res.into_body().concat2()) .wait());
                        let body = try_s! (from_utf8 (&body)) .trim();
                        Ok ((status, body.into()))
                    }

                    mm_state = match mm_state {
                        MmState::Starting => {  // See if MM started.
                            let mm_log = slurp (&mm_output);
                            let mm_log = unsafe {from_utf8_unchecked (&mm_log)};
                            if mm_log.contains (">>>>>>>>>> DEX stats 127.0.0.1:7783 bind") {MmState::Started}
                            else {MmState::Starting}
                        },
                        MmState::Started => {  // Kickstart the events stream by invoking the "getendpoint".
                            let (status, body) = unwrap! (call_mm (String::from (
                                "{\"userpass\":\"5bfaeae675f043461416861c3558146bf7623526891d890dc96bc5e0e5dbc337\",\"method\":\"getendpoint\"}")));
                            println! ("test_events] getendpoint response: {:?}, {}", status, body);
                            assert_eq! (status, StatusCode::OK);
                            assert! (body.contains ("\"endpoint\":\"ws://127.0.0.1:5555\""));
                            MmState::GetendpointSent
                        },
                        MmState::GetendpointSent => {  // Wait for the `mm2 events` test to finish.
                            let mm_events_log = slurp (&mm_events_output);
                            let mm_events_log = unsafe {from_utf8_unchecked (&mm_events_log)};
                            if mm_events_log.contains ("\"base\":\"KMD\"") && mm_events_log.contains ("\"price64\":\"") {MmState::Passed}
                            else {MmState::GetendpointSent}
                        },
                        MmState::Passed => {  // Gracefully stop the MM.
                            let (status, body) = unwrap! (call_mm (String::from (
                                "{\"userpass\":\"5bfaeae675f043461416861c3558146bf7623526891d890dc96bc5e0e5dbc337\",\"method\":\"stop\"}")));
                            println! ("test_events] stop response: {:?}, {}", status, body);
                            assert_eq! (status, StatusCode::OK);
                            assert_eq! (body, "{\"result\":\"success\"}");
                            sleep (Duration::from_millis (100));
                            let _ = fs::remove_file (mm_output);
                            let _ = fs::remove_file (mm_events_output);
                            break
                        }
                    };

                    if now_float() - started > 20. {panic! ("Test didn't pass withing the 20 seconds timeframe")}
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
        "  help  ..  Display this message.\n"
        "  btc2kmd {WIF or BTC}  ..  Convert a BTC WIF into a KMD WIF.\n"
        "  events  ..  Listen to a feed coming from a separate MM daemon and print it to stdout.\n"
        "\n"
        // Generated from https://github.com/KomodoPlatform/DocumentationPreview.
        // SHossain: "this would be the URL we would recommend and it will be maintained
        //            Please let @gcharang or me know if anything needs updating there".
        "See also the online documentation at https://docs.komodoplatform.com/barterDEX/barterDEX-API.html."
    )
}

const MM_VERSION: &'static str = env!("MM_VERSION");

fn main() {
    init_crash_reports();
    unsafe {os_portable::OS_init()};
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

    if first_arg == Some ("--help") || first_arg == Some ("-h") || first_arg == Some ("help") {help(); return}
    if cfg! (windows) && first_arg == Some ("/?") {help(); return}

    unsafe {mm1_main ((args.len() as i32) - 1, args.as_ptr());}
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
        fn bitcoin_priv2wif (symbol: *const u8, wiftaddr: u8, wifstr: *mut c_char, privkey: bits256, addrtype: u8) -> i32;
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
    use nn::*;

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

/*
    else if ( argv[1] != 0 && strcmp(argv[1],"hush") == 0 )
    {
        uint32_t timestamp; char str[65],wifstr[128]; bits256 privkey; int32_t i;
        timestamp = (uint32_t)time(NULL);
        //printf("start hush vanitygen t.%u\n",timestamp);
        for (i=0; i<1000000000; i++)
        {
            OS_randombytes(privkey.bytes,sizeof(privkey));
            privkey.bytes[0] = 0x0e;
            privkey.bytes[1] = 0x5b;
            privkey.bytes[2] = 0xf9;
            privkey.bytes[3] = 0xc6;
            privkey.bytes[4] = 0x06;
            privkey.bytes[5] = 0xdd;
            privkey.bytes[6] = 0xbb;
            bitcoin_priv2wiflong("HUSH",0xab,wifstr,privkey,0x36);
            if ( wifstr[2] == 'x' && wifstr[4] == 'H' && wifstr[5] == 'u' && wifstr[6] == 's' )//&& wifstr[3] == 'x' )
            {
                if ( wifstr[7] == 'h' && wifstr[8] == 'L' && wifstr[9] == 'i' )
                {
                    //printf("i.%d %s -> wif.%s\n",i,bits256_str(str,privkey),wifstr);
                    if ( wifstr[10] == 's' && wifstr[11] == 't' )
                    {
                        printf("{\"iters\":%d,\"privkey\":\"%s\",\"wif\":\"%s\"}\n",i,bits256_str(str,privkey),wifstr);
                        break;
                    }
                }
            } //else printf("failed %s\n",wifstr);
        }
        //printf("done hush vanitygen done %u elapsed %d\n",(uint32_t)time(NULL),(uint32_t)time(NULL) - timestamp);
        exit(0);
    }
    else if ( argv[1] != 0 && strcmp(argv[1],"vanity") == 0 && argv[2] != 0 )
    {
        uint32_t timestamp; uint8_t pubkey33[33]; char str[65],coinaddr[64],wifstr[128]; bits256 privkey; int32_t i,len; void *ctx;
        ctx = bitcoin_ctx();
        len = (int32_t)strlen(argv[2]);
        timestamp = (uint32_t)time(NULL);
        printf("start vanitygen (%s).%d t.%u\n",argv[2],len,timestamp);
        for (i=0; i<1000000000; i++)
        {
            OS_randombytes(privkey.bytes,sizeof(privkey));
            bitcoin_priv2pub(ctx,"KMD",pubkey33,coinaddr,privkey,0,60);
            if ( strncmp(coinaddr+1,argv[2],len-1) == 0 )
            {
                bitcoin_priv2wif("KMD",0,wifstr,privkey,188);
                printf("i.%d %s -> %s wif.%s\n",i,bits256_str(str,privkey),coinaddr,wifstr);
                if ( coinaddr[1+len-1] == argv[2][len-1] )
                    break;
            } //else printf("failed %s\n",wifstr);
        }
        printf("done vanitygen.(%s) done %u elapsed %d\n",argv[2],(uint32_t)time(NULL),(uint32_t)time(NULL) - timestamp);
        exit(0);
    }
    else if ( argv[1] != 0 && strcmp(argv[1],"airdropH") == 0 && argv[2] != 0 )
    {
        FILE *fp; double val,total = 0.; uint8_t checktype,addrtype,rmd160[21],checkrmd160[21]; char *floatstr,*addrstr,buf[256],checkaddr[64],coinaddr[64],manystrs[64][128],cmd[64*128]; int32_t n,i,num; char *flag;
        if ( (fp= fopen(argv[2],"rb")) != 0 )
        {
            num = 0;
            while ( fgets(buf,sizeof(buf),fp) > 0 )
            {
                if ( (n= (int32_t)strlen(buf)) > 0 )
                    buf[--n] = 0;
                flag = 0;
                for (i=0; i<n; i++)
                {
                    if ( buf[i] == ',' )
                    {
                        buf[i] = 0;
                        flag = &buf[i+1];
                        break;
                    }
                }
                if ( flag != 0 )
                {
                    addrstr = flag, floatstr = buf;
                    //addrstr = buf, floatstr = flag;
                    //bitcoin_addr2rmd160("HUSH",28,&addrtype,rmd160,buf);
                    bitcoin_addr2rmd160("BTC",0,&addrtype,rmd160,addrstr);
                    bitcoin_address("KMD",coinaddr,0,addrtype == 0 ? 60 : 85,rmd160,20);
                    bitcoin_addr2rmd160("KMD",0,&checktype,checkrmd160,coinaddr);
                    //bitcoin_address("HUSH",checkaddr,28,checktype == 60 ? 184 : 189,checkrmd160,20);
                    bitcoin_address("BTC",checkaddr,0,checktype == 60 ? 0 : 5,checkrmd160,20);
                    if ( memcmp(rmd160,checkrmd160,20) != 0 || strcmp(addrstr,checkaddr) != 0 )
                    {
                        for (i=0; i<20; i++)
                            printf("%02x",rmd160[i]);
                        printf(" vs. ");
                        for (i=0; i<20; i++)
                            printf("%02x",checkrmd160[i]);
                        printf(" address calc error (%s).%d -> (%s).%d -> (%s) %.8f?\n",addrstr,addrtype,coinaddr,checktype,checkaddr,atof(floatstr));
                    }
                    else
                    {
                        val = atof(floatstr);
                        sprintf(manystrs[num++],"\\\"%s\\\":%0.8f",coinaddr,val);
                        if ( num >= sizeof(manystrs)/sizeof(*manystrs) )
                        {
                            sprintf(cmd,"fiat/btch sendmany \\\"\\\" \"{");
                            for (i=0; i<num; i++)
                                sprintf(cmd + strlen(cmd),"%s%s",manystrs[i],i<num-1?",":"");
                            strcat(cmd,"}\" 0");
                            printf("%s\nsleep 3\n",cmd);
                            num = 0;
                            memset(manystrs,0,sizeof(manystrs));
                        }
                        total += val;
                        //printf("(%s).%d (%s) <- %.8f (%s) total %.8f\n",addrstr,addrtype,coinaddr,val,floatstr,total);
                    }
                } else printf("parse error for (%s)\n",buf);
            }
            if ( num > 0 )
            {
                sprintf(cmd,"fiat/btch sendmany \\\"\\\" \"{");
                for (i=0; i<num; i++)
                    sprintf(cmd + strlen(cmd),"%s%s",manystrs[i],i<num-1?",":"");
                strcat(cmd,"}\" 0");
                printf("%s\n",cmd);
                num = 0;
                memset(manystrs,0,sizeof(manystrs));
            }
            printf("close (%s) total %.8f\n",argv[2],total);
            fclose(fp);
        } else printf("couldnt open (%s)\n",argv[2]);
        exit(0);
    }
    sprintf(dirname,"%s",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    if ( ensure_writable(dirname) < 0 )
    {
        printf("couldnt write to (%s)\n",dirname);
        exit(0);
    }
    sprintf(dirname,"%s/SWAPS",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    if ( ensure_writable(dirname) < 0 )
    {
        printf("couldnt write to (%s)\n",dirname);
        exit(0);
    }
    sprintf(dirname,"%s/GTC",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    if ( ensure_writable(dirname) < 0 )
    {
        printf("couldnt write to (%s)\n",dirname);
        exit(0);
    }
    sprintf(dirname,"%s/PRICES",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    if ( ensure_writable(dirname) < 0 )
    {
        printf("couldnt write to (%s)\n",dirname);
        exit(0);
    }
    sprintf(dirname,"%s/UNSPENTS",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    if ( ensure_writable(dirname) < 0 )
    {
        printf("couldnt write to (%s)\n",dirname);
        exit(0);
    }
#ifdef FROM_JS
    argc = 2;
    retjson = cJSON_Parse("{\"client\":1,\"passphrase\":\"test\"}");
    printf("calling LP_main(%s)\n",jprint(retjson,0));
    LP_main(retjson);
    emscripten_set_main_loop(LP_fromjs_iter,1,0);
#else
    if ( argc == 1 )
    {
        //LP_privkey_tests();
        LP_NXT_redeems();
        sleep(3);
        return(0);
    }
    if ( argc > 1 && (retjson= cJSON_Parse(argv[1])) != 0 )
    {
        if ( jint(retjson,"docker") == 1 )
            DOCKERFLAG = 1;
        else if ( jstr(retjson,"docker") != 0 )
            DOCKERFLAG = (uint32_t)calc_ipbits(jstr(retjson,"docker"));
        //if ( jobj(retjson,"passphrase") != 0 )
        //    jdelete(retjson,"passphrase");
        //if ( (passphrase= jstr(retjson,"passphrase")) == 0 )
        //    jaddstr(retjson,"passphrase","default");
        if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_main,(void *)retjson) != 0 )
        {
            printf("error launching LP_main (%s)\n",jprint(retjson,0));
            exit(-1);
        } //else printf("(%s) launched.(%s)\n",argv[1],passphrase);
        incr = 100.;
        while ( LP_STOP_RECEIVED == 0 )
            sleep(100000);
    } else printf("couldnt parse.(%s)\n",argv[1]);
#endif
    return 0;
}

*/