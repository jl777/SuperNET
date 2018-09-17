extern crate bindgen;
extern crate cc;
extern crate duct;
extern crate gstuff;
extern crate num_cpus;
#[macro_use]
extern crate unwrap;
extern crate winapi;

use gstuff::last_modified_sec;
use std::fs;
use std::iter::empty;
use std::path::Path;

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
            builder = builder.whitelist_recursively(true);
            builder = builder.layout_tests(false);
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

fn main() {
    let _ = fs::create_dir("c_headers");
    println!("rerun-if-changed=../../iguana/exchanges/etomicswap/etomiclib.h");
    println!("rerun-if-changed=../../iguana/exchanges/etomicswap/etomiccurl.h");

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
        ].iter(),
        empty(),
    );

    if cfg!(windows) {
        // The `helpers` crate needs to access the MM1 code,
        // and on Windows this leads to linking errors in "cargo test --package etomicrs"
        // unless we link in the MM1 and the libraries it depends on.

        println!("cargo:rustc-link-lib=static=marketmaker-mainnet-lib");
        println!("cargo:rustc-link-lib=static=libcrypto777");
        println!("cargo:rustc-link-lib=static=libjpeg");
        println!("cargo:rustc-link-lib=static=libsecp256k1");

        println!("cargo:rustc-link-lib=pthreadVC2");
        println!("cargo:rustc-link-lib=static=nanomsg");
        println!("cargo:rustc-link-lib=mswsock");
        println!("cargo:rustc-link-lib=libcurl");

        println!("cargo:rustc-link-search=native=./x64");
        println!("cargo:rustc-link-search=native=./build/iguana/exchanges/Debug");
        println!("cargo:rustc-link-search=native=./build/iguana/exchanges/etomicswap/Debug");
        println!("cargo:rustc-link-search=native=./build/crypto777/Debug");
        println!("cargo:rustc-link-search=native=./build/crypto777/jpeg/Debug");
        println!("cargo:rustc-link-search=native=./build/iguana/secp256k1/Debug");
    }
}
