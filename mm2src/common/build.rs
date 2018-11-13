// The script here will translate some of the C headers necessary for the gradual Rust port into the corresponding Rust files.
// Going to take the *whitelisting* approach, converting just the necessary definitions, in order to keep the builds fast.

// The script is experimentally formatted with `rustfmt`. Probably not going to use `rustfmt` for the rest of the project though.

// Bindgen requirements: https://rust-lang-nursery.github.io/rust-bindgen/requirements.html
//              Windows: https://github.com/rust-lang-nursery/rustup.rs/issues/1003#issuecomment-289825927
// On build.rs: https://doc.rust-lang.org/cargo/reference/build-scripts.html

extern crate bindgen;
extern crate cc;
extern crate duct;
extern crate gstuff;
extern crate num_cpus;
#[macro_use]
extern crate unwrap;
extern crate winapi;

use duct::cmd;
use gstuff::last_modified_sec;
use std::env;
use std::fs;
use std::io::Read;
use std::iter::empty;
use std::path::{Path, PathBuf};

/// Ongoing (RLS) builds might interfere with a precise time comparison.
const SLIDE: f64 = 60.;

fn bindgen<
    'a,
    TP: AsRef<Path>,
    FI: Iterator<Item = &'a &'a str>,
    TI: Iterator<Item = &'a &'a str>,
    DI: Iterator<Item = &'a &'a str>,
>(
    from: Vec<String>,
    to: TP,
    functions: FI,
    types: TI,
    defines: DI,
) {
    // We'd like to regenerate the bindings whenever the build.rs changes, in case we changed bindgen configuration here.
    let lm_build_rs = unwrap!(last_modified_sec(&"build.rs"), "Can't stat build.rs");

    let to = to.as_ref();

    let mut lm_from = 0f64;
    for header_path in &from {
        lm_from = match last_modified_sec(&header_path) {
            Ok(sec) => lm_from.max(sec),
            Err(err) => panic!("Can't stat the header {:?}: {}", from, err),
        };
    }
    let lm_to = last_modified_sec(&to).unwrap_or(0.);
    if lm_from >= lm_to - SLIDE || lm_build_rs >= lm_to - SLIDE {
        let bindings = {
            // https://docs.rs/bindgen/0.37.*/bindgen/struct.Builder.html
            let mut builder = bindgen::builder();
            for header_path in from {
                builder = builder.header(header_path)
            }
            builder = builder.ctypes_prefix("::libc");
            builder = builder.whitelist_recursively(true);
            builder = builder.layout_tests(false);
            builder = builder.derive_default(true);
            // Currently works for functions but not for variables such as `extern uint32_t DOCKERFLAG`.
            builder = builder.generate_comments(true);
            if cfg!(windows) {
                // Normally we should be checking for `_WIN32`, but `nn_config.h` checks for `WIN32`.
                // (Note that it's okay to have WIN32 defined for 64-bit builds,
                // cf https://github.com/rust-lang-nursery/rust-bindgen/issues/1062#issuecomment-334804738).
                builder = builder.clang_arg("-D WIN32");
            }
            for name in functions {
                builder = builder.whitelist_function(name)
            }
            for name in types {
                builder = builder.whitelist_type(name)
            }
            // Looks like C defines should be whitelisted both on the function and the variable levels.
            for name in defines {
                builder = builder.whitelist_function(name);
                builder = builder.whitelist_var(name)
            }
            match builder.generate() {
                Ok(bindings) => bindings,
                Err(()) => panic!("Error generating the bindings for {:?}", to),
            }
        };

        if let Err(err) = bindings.write_to_file(to) {
            panic!("Error writing to {:?}: {}", to, err)
        }
    }
}

fn generate_bindings() {
    let _ = fs::create_dir("c_headers");

    bindgen(
        vec![
            "../../iguana/exchanges/etomicswap/etomiclib.h".into(),
            "../../iguana/exchanges/etomicswap/etomiccurl.h".into(),
        ],
        "c_headers/etomiclib.rs",
        empty(),
        [
            "AliceSendsEthPaymentInput",
            "AliceSendsErc20PaymentInput",
            "AliceReclaimsPaymentInput",
            "BobSpendsAlicePaymentInput",
            "BobSendsEthDepositInput",
            "BobSendsErc20DepositInput",
            "BobRefundsDepositInput",
            "AliceClaimsBobDepositInput",
            "BobSendsEthPaymentInput",
            "BobSendsErc20PaymentInput",
            "BobReclaimsBobPaymentInput",
            "AliceSpendsBobPaymentInput",
            "ApproveErc20Input",
            "EthTxReceipt",
            "EthTxData",
        ]
            .iter(),
        empty(),
    );

    // NB: curve25519.h and cJSON.h are needed to parse LP_include.h.
    bindgen(
        vec![
            "../../includes/curve25519.h".into(),
            "../../includes/cJSON.h".into(),
            "../../iguana/exchanges/LP_include.h".into(),
        ],
        "c_headers/LP_include.rs",
        [
            // functions
            "cJSON_Parse",
            "cJSON_GetErrorPtr",
            "cJSON_Delete",
            "cJSON_GetArraySize",
            "j64bits",
            "jadd",
            "jarray",
            "jitem",
            "jint",
            "juint",
            "jstr",
            "jdouble",
            "jobj",
            "jprint",
            "free_json",
            "jaddstr",
            "unstringify",
            "jaddnum",
            "LP_NXT_redeems",
            "LPinit",
            "LP_addpeer",
            "LP_peer_recv",
            "LP_initpublicaddr",
            "LP_ports",
            "unbuffered_output_support",
            "calc_crc32",
            "LP_initcoins",
            "LP_mutex_init",
            "LP_tradebots_timeslice",
            "stats_JSON",
            "LP_priceinfofind",
            "prices_loop",
            "LP_portfolio",
            "LP_coinfind",
            "LP_coinjson",
            "LP_portfolio_trade",
            "LP_portfolio_order",
            "LP_pricesparse",
            "LP_ticker",
            "LP_queuecommand",
            "LP_CMCbtcprice",
            "LP_fundvalue",
            "LP_coinsearch",
            "LP_autoprice",
            "LP_instantdex_deposit",
            "LP_mypriceset",
            "LP_pricepings",
            "LP_autopriceset",
            "LP_alicequery_clear",
            "LP_address_utxo_reset",
            "LP_autosplit",
            "LP_txfees",
            "LP_address_minmax",
            "LP_fomoprice",
            "LP_quoteinfoinit",
            "LP_quotedestinfo",
            "gen_quote_uuid",
            "decode_hex",
            "LP_aliceid_calc",
            "LP_rand",
            "LP_query",
            "LP_quotejson",
            "LP_mpnet_send",
            "LP_recent_swaps",
            "LP_address",
            "LP_address_utxo_ptrs",
            "LP_command_process",
            "LP_balances",
            "LP_KMDvalue",
            "LP_quoteparse",
            "LP_requestinit",
            "LP_tradecommand_log",
            "bits256_str", // cf. `impl fmt::Display for bits256`
            "vcalc_sha256",
            "calc_rmd160_sha256",
            "bitcoin_address",
            "bitcoin_pubkey33",
            "LP_alice_eligible",
            "LP_quotecmp",
            "LP_instantdex_proofcheck",
            "LP_myprice",
            "LP_pricecache",
            "LP_pricevalid",
            "LP_pubkeyadd",
            "LP_pubkeyfind",
            "LP_pubkey_sigcheck",
            "LP_aliceid",
            "LP_quotereceived",
            "LP_dynamictrust",
            "LP_kmdvalue",
            "LP_trades_alicevalidate",
            "LP_failedmsg",
            "LP_abutxo_set",
            "LP_quote_validate",
            "LP_availableset",
            "LP_closepeers",
            "LP_tradebot_pauseall",
            "LP_portfolio_reset",
            "LP_priceinfos_clear",
            "LP_privkey_updates",
            "LP_privkey_init",
            "LP_privkey",
            "LP_swapinit",
            "LP_importaddress",
            "LP_otheraddress",
            "LP_swapsfp_update",
            "LP_aliceloop",
            "LP_reserved_msg",
            "LP_unavailableset",
            "LP_trades_pricevalidate",
            "LP_allocated",
            "LP_basesatoshis",
            "LP_trades_bobprice",
            "LP_RTmetrics_blacklisted",
            "LP_getheight",
            "LP_reservation_check",
            "LP_nanobind",
            "LP_bobloop",
            "LP_instantdex_txids",
        ]
            .iter(),
        // types
        [
            "_bits256",
            "cJSON",
            "iguana_info",
            "LP_utxoinfo",
            "electrum_info",
            "LP_trade",
        ]
            .iter(),
        [
            // defines
            "LP_eth_node_url",
            "LP_alice_contract",
            "LP_bob_contract",
            "bitcoind_RPC_inittime",
            "GLOBAL_DBDIR",
            "DOCKERFLAG",
            "USERHOME",
            "LP_profitratio",
            "LP_RPCPORT",
            "LP_MAXPRICEINFOS",
            "LP_showwif",
            "LP_coins",
            "IAMLP",
            "LP_gui",
            "LP_canbind",
            "LP_fixed_pairport",
            "LP_myipaddr",
            "LP_myipaddr_from_command_line",
            "LP_autoprices",
            "num_LP_autorefs",
            "LP_STOP_RECEIVED",
            "IPC_ENDPOINT",
            "SPAWN_RPC",
            "LP_autorefs",
            "G",
            "LP_mypubsock",
            "LP_mypullsock",
            "LP_mypeer",
            "RPC_port",
            "LP_ORDERBOOK_DURATION",
            "LP_AUTOTRADE_TIMEOUT",
            "LP_RESERVETIME",
            "Alice_expiration",
            "LP_Alicequery",
            "LP_Alicemaxprice",
            "LP_Alicedestpubkey",
            "GTCorders",
            "LP_QUEUE_COMMAND",
            "LP_RTcount",
            "LP_swapscount",
            "LP_REQUEST",
            "LP_RESERVED",
            "LP_CONNECT",
            "LP_CONNECTED",
            "LP_Alicereserved",
            "dstr",
        ]
            .iter(),
    );

    bindgen(
        vec!["../../crypto777/OS_portable.h".into()],
        "c_headers/OS_portable.rs",
        [
            // functions
            "OS_init",
            "OS_ensure_directory",
            "OS_compatible_path",
            "calc_ipbits",
        ]
            .iter(),
        empty(), // types
        empty(), // defines
    );
    bindgen(
        vec!["../../crypto777/nanosrc/nn.h".into()],
        "c_headers/nn.rs",
        [
            "nn_bind",
            "nn_connect",
            "nn_close",
            "nn_errno",
            "nn_freemsg",
            "nn_recv",
            "nn_setsockopt",
            "nn_send",
            "nn_socket",
            "nn_strerror",
        ]
            .iter(),
        empty(),
        ["AF_SP", "NN_PAIR", "NN_PUB", "NN_SOL_SOCKET", "NN_SNDTIMEO"].iter(),
    );
}

/// The build script will usually help us by putting the MarketMaker version
/// into the "MM_VERSION" environment or the "MM_VERSION" file.
/// If neither is there then we're probably in a non-released, local development branch
/// (we're using the "UNKNOWN" version designator then).
/// This function ensures that we have the "MM_VERSION" variable during the build.
fn mm_version() -> String {
    if let Some(have) = option_env!("MM_VERSION") {
        // The variable is already there.
        return have.into();
    }

    // Try to load the variable from the file.
    let mut buf;
    let version = if let Ok(mut file) = fs::File::open("../../MM_VERSION") {
        buf = String::new();
        unwrap!(file.read_to_string(&mut buf), "Can't read from MM_VERSION");
        buf.trim()
    } else {
        "UNKNOWN"
    };
    println!("cargo:rustc-env=MM_VERSION={}", version);
    version.into()
}

/// Formats a vector of command-line arguments into a printable string, for the build log.
fn show_args<'a, I: IntoIterator<Item = &'a String>>(args: I) -> String {
    use std::fmt::Write;
    let mut buf = String::new();
    for arg in args {
        if arg.contains(' ') {
            let _ = write!(&mut buf, " \"{}\"", arg);
        } else {
            buf.push(' ');
            buf.push_str(arg)
        }
    }
    buf
}

/// See if we have the required libraries.
#[cfg(windows)]
fn windows_requirements() {
    use std::ffi::OsString;
    use std::mem::uninitialized;
    use std::os::windows::ffi::OsStringExt;
    use std::path::Path;
    // https://msdn.microsoft.com/en-us/library/windows/desktop/ms724373(v=vs.85).aspx
    use winapi::um::sysinfoapi::GetSystemDirectoryW;

    let system = {
        let mut buf: [u16; 1024] = unsafe { uninitialized() };
        let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), (buf.len() - 1) as u32) };
        if len <= 0 {
            panic!("!GetSystemDirectoryW")
        }
        let len = len as usize;
        let system = OsString::from_wide(&buf[0..len]);
        Path::new(&system).to_path_buf()
    };
    eprintln!("windows_requirements] System directory is {:?}.", system);

    // `msvcr100.dll` is required by `ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-9-1-release/dll/x64/pthreadVC2.dll`
    let msvcr100 = system.join("msvcr100.dll");
    if !msvcr100.exists() {
        panic! ("msvcr100.dll is missing. \
            You can install it from https://www.microsoft.com/en-us/download/details.aspx?id=14632.");
    }

    // I don't exactly know what DLLs this download installs. Probably "msvcp140...". Might prove useful later.
    //You can install it from https://aka.ms/vs/15/release/vc_redist.x64.exe,
    //see https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads
}

#[cfg(not(windows))]
fn windows_requirements() {}

/// SuperNET's root.
fn root() -> PathBuf {
    let common = Path::new(env!("CARGO_MANIFEST_DIR"));
    let super_net = common.join("../..");
    let super_net = match super_net.canonicalize() {
        Ok(p) => p,
        Err(err) => panic!("Can't canonicalize {:?}: {}", super_net, err),
    };
    // On Windows we're getting these "\\?\" paths from canonicalize but they aren't any good for CMake.
    if cfg!(windows) {
        let s = path2s(super_net);
        Path::new(if s.starts_with(r"\\?\") {
            &s[4..]
        } else {
            &s[..]
        })
        .into()
    } else {
        super_net
    }
}

/// Absolute path taken from SuperNET's root + `path`.  
fn rabs(rrel: &str) -> PathBuf {
    root().join(rrel)
}

fn path2s(path: PathBuf) -> String {
    unwrap!(path.to_str(), "Non-stringy path {:?}", path).into()
}

fn libtorrent() {
    // TODO: If we decide to keep linking with libtorrent then we should distribute the
    //       https://github.com/arvidn/libtorrent/blob/master/LICENSE.

    if cfg!(windows) {
        /* As of now we're using a manual build to experiment with libtorrent.
        wget https://dl.bintray.com/boostorg/release/1.68.0/source/boost_1_68_0.zip
        unzip boost_1_68_0.zip
        cd boost_1_68_0
        bootstrap
        # cf. https://stackoverflow.com/questions/10022180/how-to-build-boost-required-modules-only
        b2 release toolset=msvc-14.1 address-model=64 link=static stage --with-date_time --with-system
        cd ..
        set PATH=%PATH%;c:\spool\synced\komodo\SuperNET\x64\boost_1_68_0
        set BOOST_BUILD_PATH=c:\spool\synced\komodo\SuperNET\x64\boost_1_68_0
        set BOOST_ROOT=c:\spool\synced\komodo\SuperNET\x64\boost_1_68_0
        b2 --version
        git clone --depth=1 git@github.com:arvidn/libtorrent.git
        cd libtorrent
        b2 release toolset=msvc-14.1 address-model=64 link=static dht=on debug-symbols=off
        */

        let lib = root().join(r"x64\libtorrent\bin\msvc-14.1\release\address-model-64\link-static\threading-multi\libtorrent.lib");
        let bl = root().join (r"x64\boost_1_68_0\stage\lib");
        if lib.exists() && bl.exists() {
            let lm_dht = unwrap!(last_modified_sec(&"dht.cc"), "Can't stat dht.cc");
            let out_dir = unwrap!(env::var("OUT_DIR"), "!OUT_DIR");
            let lib_path = Path::new(&out_dir).join("libdht.a");
            let lm_lib = last_modified_sec(&lib_path).unwrap_or(0.);
            if lm_dht >= lm_lib - SLIDE {
                cc::Build::new()
                    .file("dht.cc")
                    .warnings(true)
                    .include(r"..\..\x64\libtorrent\include")
                    .include(r"..\..\x64\boost_1_68_0")
                    // https://docs.microsoft.com/en-us/cpp/porting/modifying-winver-and-win32-winnt?view=vs-2017
                    .define("_WIN32_WINNT", "0x0600")
                    // cf. https://stackoverflow.com/questions/4573536/ehsc-vc-eha-synchronous-vs-asynchronous-exception-handling
                    .flag ("/EHsc")
                    .compile("dht");
            }
            println!("cargo:rustc-link-lib=static=dht");
            println!("cargo:rustc-link-search=native={}", out_dir);

            println!("cargo:rustc-link-lib=static=libtorrent");
            println!(
                "cargo:rustc-link-search=native={}",
                unwrap!(unwrap!(lib.parent()).to_str())
            );

            println!("cargo:rustc-link-lib=static=libboost_system-vc141-mt-x64-1_68");
            println!("cargo:rustc-link-lib=static=libboost_date_time-vc141-mt-x64-1_68");
            println!("cargo:rustc-link-search=native={}", unwrap!(bl.to_str()));

            println!("cargo:rustc-link-lib=iphlpapi"); // NotifyAddrChange.
        }
    }
}

/// Build helper C code.
///
/// I think "git clone ... && cargo build" should be enough to start hacking on the Rust code.
///
/// For now we're building the Structured Exception Handling code here,
/// but in the future we might subsume the rest of the C build under build.rs.
fn build_c_code(mm_version: &str) {
    // Link in the Windows-specific crash handling code.

    if cfg!(windows) {
        let lm_seh = unwrap!(last_modified_sec(&"seh.c"), "Can't stat seh.c");
        let out_dir = unwrap!(env::var("OUT_DIR"), "!OUT_DIR");
        let lib_path = Path::new(&out_dir).join("libseh.a");
        let lm_lib = last_modified_sec(&lib_path).unwrap_or(0.);
        if lm_seh >= lm_lib - SLIDE {
            cc::Build::new().file("seh.c").warnings(true).compile("seh");
        }
        println!("cargo:rustc-link-lib=static=seh");
        println!("cargo:rustc-link-search=native={}", out_dir);
    }

    // The MM1 library.

    let _ = fs::create_dir(root().join("build"));
    let _ = fs::create_dir_all(root().join("target/debug"));

    // NB: With "duct 0.11.0" the `let _` variable binding is necessary in order for the build not to fall detached into background.
    let mut cmake_prep_args: Vec<String> = Vec::new();
    if cfg!(windows) {
        // To flush the build problems early we explicitly specify that we want a 64-bit MSVC build and not a GNU or 32-bit one.
        cmake_prep_args.push("-G".into());
        cmake_prep_args.push("Visual Studio 15 2017 Win64".into());
    }
    cmake_prep_args.push("-DETOMIC=ON".into());
    cmake_prep_args.push(format!("-DMM_VERSION={}", mm_version));
    cmake_prep_args.push("-DCMAKE_BUILD_TYPE=Debug".into());
    cmake_prep_args.push("..".into());
    eprintln!("$ cmake{}", show_args(&cmake_prep_args));
    let _ = unwrap!(
        cmd("cmake", cmake_prep_args)
            .dir(root().join("build"))
            .stdout_to_stderr() // NB: stderr is visible through "cargo build -vv".
            .run(),
        "!cmake"
    );

    let mut cmake_args: Vec<String> = vec![
        "--build".into(),
        ".".into(),
        "--target".into(),
        "marketmaker-lib".into(),
    ];
    if !cfg!(windows) {
        // Doesn't currently work on AppVeyor.
        cmake_args.push("-j".into());
        cmake_args.push(format!("{}", num_cpus::get()));
    }
    eprintln!("$ cmake{}", show_args(&cmake_args));
    let _ = unwrap!(
        cmd("cmake", cmake_args)
            .dir(root().join("build"))
            .stdout_to_stderr() // NB: stderr is visible through "cargo build -vv".
            .run(),
        "!cmake"
    );

    println!("cargo:rustc-link-lib=static=marketmaker-lib");

    // Link in the libraries needed for MM1.

    println!("cargo:rustc-link-lib=static=libcrypto777");
    println!("cargo:rustc-link-lib=static=libjpeg");
    //Already linked from etomicrs->ethkey->eth-secp256k1//println!("cargo:rustc-link-lib=static=libsecp256k1");

    if cfg!(windows) {
        println!("cargo:rustc-link-search=native={}", path2s(rabs("x64")));
        // When building locally with CMake 3.12.0 on Windows the artefacts are created in the "Debug" folders:
        println!(
            "cargo:rustc-link-search=native={}",
            path2s(rabs("build/iguana/exchanges/Debug"))
        );
        println!(
            "cargo:rustc-link-search=native={}",
            path2s(rabs("build/crypto777/Debug"))
        );
        println!(
            "cargo:rustc-link-search=native={}",
            path2s(rabs("build/crypto777/jpeg/Debug"))
        );
    // https://stackoverflow.com/a/10234077/257568
    //println!(r"cargo:rustc-link-search=native=c:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\Tools\MSVC\14.14.26428\lib\x64");
    } else {
        println!(
            "cargo:rustc-link-search=native={}",
            path2s(rabs("build/iguana/exchanges"))
        );
        println!(
            "cargo:rustc-link-search=native={}",
            path2s(rabs("build/crypto777"))
        );
        println!(
            "cargo:rustc-link-search=native={}",
            path2s(rabs("build/crypto777/jpeg"))
        );
        println!(
            "cargo:rustc-link-search=native={}",
            path2s(rabs("build/nanomsg-build"))
        );
    }

    println!(
        "cargo:rustc-link-lib={}",
        if cfg!(windows) { "libcurl" } else { "curl" }
    );
    if cfg!(windows) {
        // https://sourceware.org/pthreads-win32/
        // ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-9-1-release/
        println!("cargo:rustc-link-lib=pthreadVC2");
        println!("cargo:rustc-link-lib=static=nanomsg");
        println!("cargo:rustc-link-lib=mswsock"); // For nanomsg.
        unwrap!(
            fs::copy(
                root().join("x64/pthreadVC2.dll"),
                root().join("target/debug/pthreadVC2.dll")
            ),
            "Can't copy pthreadVC2.dll"
        );
        unwrap!(
            fs::copy(
                root().join("x64/libcurl.dll"),
                root().join("target/debug/libcurl.dll")
            ),
            "Can't copy libcurl.dll"
        );
    } else {
        println!("cargo:rustc-link-lib=crypto");
        println!("cargo:rustc-link-lib=static=nanomsg");
    }
}

fn main() {
    // NB: `rerun-if-changed` will ALWAYS invoke the build.rs if the target does not exists.
    // cf. https://github.com/rust-lang/cargo/issues/4514#issuecomment-330976605
    //     https://github.com/rust-lang/cargo/issues/4213#issuecomment-310697337
    // `RUST_LOG=cargo::core::compiler::fingerprint cargo build` shows the fingerprit files used.

    // Rebuild when we work with C files.
    println!(
        "rerun-if-changed={}",
        path2s(rabs("iguana/exchanges/etomicswap"))
    );
    println!("rerun-if-changed={}", path2s(rabs("iguana/exchanges")));
    println!("rerun-if-changed={}", path2s(rabs("iguana/secp256k1")));
    println!("rerun-if-changed={}", path2s(rabs("crypto777")));
    println!("rerun-if-changed={}", path2s(rabs("crypto777/jpeg")));
    println!("rerun-if-changed={}", path2s(rabs("OSlibs/win")));
    println!("rerun-if-changed={}", path2s(rabs("CMakeLists.txt")));

    // NB: Using `rerun-if-env-changed` disables the default dependency heuristics.
    // cf. https://github.com/rust-lang/cargo/issues/4587
    // We should avoid using it for now.

    // Rebuild when we change certain features.
    //println!("rerun-if-env-changed=CARGO_FEATURE_ETOMIC");
    //println!("rerun-if-env-changed=CARGO_FEATURE_NOP");

    // Used with mm2-nop.rs in order to separately the dependencies build from the MM1 C build.
    if env::var_os("CARGO_FEATURE_NOP").is_some() {
        return;
    }

    windows_requirements();
    libtorrent();
    let mm_version = mm_version();
    build_c_code(&mm_version);
    generate_bindings();
}
