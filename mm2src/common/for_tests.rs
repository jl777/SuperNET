//! Helpers used in the unit and integration tests.

use chrono::Local;

use duct::Handle;

use futures::Future;

use gstuff::{now_float, slurp, ISATTY};

use hyper::{Request, StatusCode, HeaderMap};

use serde_json::{self as json, Value as Json};

use term;

use rand::{thread_rng, Rng};

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::str::{from_utf8};
use std::sync::Mutex;
use std::thread::{sleep};
use std::time::Duration;

use super::slurp_req;

/// Automatically kill a wrapped process.
pub struct RaiiKill {handle: Handle, running: bool}
impl RaiiKill {
    pub fn from_handle (handle: Handle) -> RaiiKill {
        RaiiKill {handle, running: true}
    }
    pub fn running (&mut self) -> bool {
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

/// When `drop`ped, dumps the given file to the stdout.
/// 
/// Used in the tests, copying the MM log to the test output.
/// 
/// Note that because of https://github.com/rust-lang/rust/issues/42474 it's currently impossible to share the MM log interactively,
/// hence we're doing it in the `drop`.
pub struct RaiiDump {
    pub log_path: PathBuf
}
impl Drop for RaiiDump {
    fn drop (&mut self) {
        // `term` bypasses the stdout capturing, we should only use it if the capturing was disabled.
        let nocapture = env::args().any (|a| a == "--nocapture");

        let log = slurp (&self.log_path);

        // Make sure the log is Unicode.
        // We'll get the "io error when listing tests: Custom { kind: InvalidData, error: StringError("text was not valid unicode") }" otherwise.
        let log = String::from_utf8_lossy (&log);
        let log = log.trim();

        if let (true, true, Some (mut t)) = (nocapture, *ISATTY, term::stdout()) {
            let _ = t.fg (term::color::BRIGHT_YELLOW);
            let _ = t.write (format! ("vvv {:?} vvv\n", self.log_path) .as_bytes());
            let _ = t.fg (term::color::YELLOW);
            let _ = t.write (log.as_bytes());
            let _ = t.write (b"\n");
            let _ = t.reset();
        } else {
            log! ({"vvv {:?} vvv\n{}", self.log_path, log});
        }
    }
}

lazy_static! {
    /// A singleton with the IPs used by the MarketMakerIt instances created in this session.
    static ref MM_IPS: Mutex<HashSet<IpAddr>> = Mutex::new (HashSet::new());
}

/// An instance of a MarketMaker process started by and for an integration test.  
/// Given that [in CI] the tests are executed before the build, the binary of that process is the tests binary.
pub struct MarketMakerIt {
    /// The MarketMaker's current folder where it will try to open the database files.
    pub folder: PathBuf,
    /// Unique (to run multiple instances) IP, like "127.0.0.$x".
    pub ip: IpAddr,
    /// The file we redirected the standard output and error streams to.
    pub log_path: PathBuf,
    /// The PID of the MarketMaker process.
    pub pc: Option<RaiiKill>,
    /// RPC API key.
    pub userpass: String
}
impl MarketMakerIt {
    /// Create a new temporary directory and start a new MarketMaker process there.
    /// 
    /// * `conf` - The command-line configuration passed to the MarketMaker.
    ///            Unique local IP address is injected as "myipaddr" unless this field is already present.
    /// * `userpass` - RPC API key. We should probably extract it automatically from the MM log.
    /// * `local` - Function to start the MarketMaker in a local thread, instead of spawning a process.
    pub fn start (mut conf: Json, userpass: String, local: Option<fn (folder: PathBuf, log_path: PathBuf, conf: Json)>)
    -> Result<MarketMakerIt, String> {
        let executable = try_s! (env::args().next().ok_or ("No program name"));
        let executable = try_s! (Path::new (&executable) .canonicalize());

        let ip: IpAddr = if conf["myipaddr"].is_null() {  // Generate an unique IP.
            let mut attempts = 0;
            let mut rng = thread_rng();
            loop {
                let ip4 = if cfg! (target_os = "macos") {
                    // For some reason we can't use the 127.0.0.2-255 range of IPs on Travis/MacOS,
                    // cf. https://travis-ci.org/artemii235/SuperNET/jobs/428167579
                    // I plan to later look into this, but for now we're always using 127.0.0.1 on MacOS.
                    //
                    // P.S. 127.0.0.2:7783 works when tested with static+cURL,
                    // cf. https://travis-ci.org/artemii235/SuperNET/builds/428350505
                    // but with MM it mysteriously fails,
                    // cf. https://travis-ci.org/artemii235/SuperNET/jobs/428341581#L4534.
                    // I think that something might be wrong with the HTTP server on our side.
                    // Hopefully porting it to Hyper (https://github.com/artemii235/SuperNET/issues/155) will help.
                    if attempts > 0 {sleep (Duration::from_millis (1000 + attempts * 200))}
                    Ipv4Addr::new (127, 0, 0, 1)
                } else {
                    Ipv4Addr::new (127, 0, 0, rng.gen_range (1, 255))
                };
                if attempts > 128 {return ERR! ("Out of local IPs?")}
                let ip: IpAddr = ip4.clone().into();
                let mut mm_ips = try_s! (MM_IPS.lock());
                if mm_ips.contains (&ip) {attempts += 1; continue}
                mm_ips.insert (ip.clone());
                conf["myipaddr"] = format! ("{}", ip) .into();
                conf["rpcip"] = format! ("{}", ip) .into();

                if cfg! (target_os = "macos") && ip4.octets()[3] > 1 {
                    // Make sure the local IP is enabled on MAC (and in the Travis CI).
                    // cf. https://superuser.com/a/458877
                    let cmd = cmd! ("sudo", "ifconfig", "lo0", "alias", format! ("{}", ip), "up");
                    match cmd.stderr_to_stdout().read() {
                        Err (err) => log! ({"MarketMakerIt] Error trying to `up` the {}: {}", ip, err}),
                        Ok (output) => log! ({"MarketMakerIt] Upped the {}: {}", ip, output})
                    }
                }
                break ip
            }
        } else {  // Just use the IP given in the `conf`.
            let ip: IpAddr = try_s! (try_s! (conf["myipaddr"].as_str().ok_or ("myipaddr is not a string")) .parse());
            let mut mm_ips = try_s! (MM_IPS.lock());
            if mm_ips.contains (&ip) {log! ({"MarketMakerIt] Warning, IP {} was already used.", ip})}
            mm_ips.insert (ip.clone());
            ip
        };

        // Use a separate (unique) temporary folder for each MM.
        // (We could also remove the old folders after some time in order not to spam the temporary folder.
        // Though we don't always want to remove them right away, allowing developers to check the files).
        let now = Local::now();
        let folder = format! ("mm2_{}_{}", now.format ("%Y-%m-%d_%H-%M-%S-%3f"), ip);
        let folder = env::temp_dir().join (folder);
        try_s! (fs::create_dir (&folder));
        let db_dir = folder.join ("DB");
        conf["dbdir"] = unwrap! (db_dir.to_str()) .into();

        try_s! (fs::create_dir (db_dir));
        let log_path = folder.join ("mm2.log");
        conf["log"] = unwrap! (log_path.to_str()) .into();

        // If `local` is provided
        // then instead of spawning a process we start the MarketMaker in a local thread,
        // allowing us to easily *debug* the tested MarketMaker code.
        // Note that this should only be used while running a single test,
        // using this option while running multiple tests (or multiple MarketMaker instances) is currently UB.
        let pc = if let Some (local) = local {
            local (folder.clone(), log_path.clone(), conf);
            None
        } else {
            Some (RaiiKill::from_handle (try_s! (cmd! (&executable, "test_mm_start", "--nocapture")
                .dir (&folder)
                .env ("_MM2_TEST_CONF", try_s! (json::to_string (&conf)))
                .env ("MM2_UNBUFFERED_OUTPUT", "1")
                .stderr_to_stdout().stdout (&log_path) .start())))
        };

        Ok (MarketMakerIt {folder, ip, log_path, pc, userpass})
    }
    pub fn log_as_utf8 (&self) -> Result<String, String> {
        let mm_log = slurp (&self.log_path);
        Ok (unsafe {String::from_utf8_unchecked (mm_log)})
    }
    /// Busy-wait on the log until the `pred` returns `true` or `timeout_sec` expires.
    pub fn wait_for_log (&self, timeout_sec: f64, pred: &Fn (&str) -> bool) -> Result<(), String> {
        let start = now_float();
        let ms = 50 .min ((timeout_sec * 1000.) as u64 / 20 + 10);
        loop {
            let mm_log = try_s! (self.log_as_utf8());
            if pred (&mm_log) {return Ok(())}
            if now_float() - start > timeout_sec {return ERR! ("Timeout expired waiting for a log condition")}
            sleep (Duration::from_millis (ms));
        }
    }
    /// Invokes the locally running MM and returns it's reply.
    pub fn rpc (&self, payload: Json) -> Result<(StatusCode, String, HeaderMap), String> {
        let payload = try_s! (json::to_string (&payload));
        let uri = format! ("http://{}:7783", self.ip);
        let request = try_s! (Request::builder().method ("POST") .uri (uri) .body (payload.into()));
        let (status, headers, body) = try_s! (slurp_req (request) .wait());
        Ok ((status, try_s! (from_utf8 (&body)) .trim().into(), headers))
    }
    /// Sends the &str payload to the locally running MM and returns it's reply.
    pub fn rpc_str (&self, payload: &'static str) -> Result<(StatusCode, String, HeaderMap), String> {
        let uri = format! ("http://{}:7783", self.ip);
        let request = try_s! (Request::builder().method ("POST") .uri (uri) .body (payload.into()));
        let (status, headers, body) = try_s! (slurp_req (request) .wait());
        Ok ((status, try_s! (from_utf8 (&body)) .trim().into(), headers))
    }
    /// Send the "stop" request to the locally running MM.
    pub fn stop (&self) -> Result<(), String> {
        let (status, body, _headers) = try_s! (self.rpc (json! ({"userpass": self.userpass, "method": "stop"})));
        if status != StatusCode::OK {return ERR! ("MM didn't accept a stop. body: {}", body)}
        Ok(())
    }
}
impl Drop for MarketMakerIt {
    fn drop (&mut self) {
        if let Ok (mut mm_ips) = MM_IPS.lock() {
            mm_ips.remove (&self.ip);
        } else {log! ("MarketMakerIt] Can't lock MM_IPS.")}
    }
}
