// The script here will translate some of the C headers necessary for the gradual Rust port into the corresponding Rust files.
// Going to take the *whitelisting* approach, converting just the necessary definitions, in order to keep the builds fast.

// The script is experimentally formatted with `rustfmt`. Probably not going to use `rustfmt` for the rest of the project though.

// Bindgen requirements: https://rust-lang-nursery.github.io/rust-bindgen/requirements.html
//              Windows: https://github.com/rust-lang-nursery/rustup.rs/issues/1003#issuecomment-289825927
// On build.rs: https://doc.rust-lang.org/cargo/reference/build-scripts.html

extern crate bindgen;
extern crate cc;
#[macro_use]
extern crate duct;
extern crate gstuff;

use gstuff::last_modified_sec;
use std::env;
use std::fs;
use std::io::Read;

const OS_PORTABLE_FUNCTIONS: [&'static str; 1] = ["OS_init"];

// Will probably refactor in the future (to be generic over multiple headers),
// right now we're in the "collect as much information as possible" phase (https://www.agilealliance.org/glossary/simple-design).
fn generate_bindings() {
    // We'd like to regenerate the bindings whenever the build.rs changes, in case we changed bindgen configuration here.
    let lm_build_rs = last_modified_sec(&"build.rs").expect("Can't stat build.rs");

    let from = "crypto777/OS_portable.h";
    let to = "crypto777/OS_portable.rs";
    let lm_from = match last_modified_sec(&from) {
        Ok(sec) => sec,
        Err(err) => panic!("Can't stat the header {}: {}", from, err),
    };
    let lm_to = last_modified_sec(&to).unwrap_or(0.);
    if lm_from >= lm_to || lm_build_rs >= lm_to {
        let bindings = {
            // https://docs.rs/bindgen/0.37.*/bindgen/struct.Builder.html
            let mut builder = bindgen::builder().header(from);
            for name in OS_PORTABLE_FUNCTIONS.iter() {
                builder = builder.whitelist_function(name)
            }
            match builder.generate() {
                Ok(bindings) => bindings,
                Err(()) => panic!("Error generating the bindings for {}", from),
            }
        };

        if let Err(err) = bindings.write_to_file(to) {
            panic!("Error writing to {}: {}", to, err)
        }
    }
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
    let version = if let Ok(mut file) = fs::File::open("MM_VERSION") {
        buf = String::new();
        file.read_to_string(&mut buf)
            .expect("Can't read from MM_VERSION");
        buf.trim()
    } else {
        "UNKNOWN"
    };
    println!("cargo:rustc-env=MM_VERSION={}", version);
    version.into()
}

/// Build helper C code.
///
/// I think "git clone ... && cargo build" should be enough to start hacking on the Rust code.
///
/// For now we're building the Structured Exception Handling code here,
/// but in the future we might subsume the rest of the C build under build.rs.
fn build_c_code(mm_version: &str) {
    if cfg!(windows) {
        // TODO: Only (re)build the library when the source code or the build script changes.
        cc::Build::new()
            .file("OSlibs/win/seh.c")
            .warnings(true)
            .compile("seh");
        println!("cargo:rustc-link-lib=static=seh");
        println!(
            "cargo:rustc-link-search=native={}",
            env::var("OUT_DIR").expect("!OUT_DIR")
        );
    }

    // In CI and Docker we're building MM1 separately, in order to benefit from granular caching and verbose logs.
    // But we also want "git clone ... && cargo build" to *just work*,
    // so if the MM1 build haven't happened *yet* then we invoke it from here.
    if last_modified_sec(&"build").unwrap_or(0.) == 0. {
        fs::create_dir("build").expect("Can't create the 'build' directory");

        // NB: With "0.11.0" the `let _` variable binding is necessary in order for the build not to fall detached into background.
        let _ = cmd!("cmake", format!("-DMM_VERSION={}", mm_version), "..")
            .dir("build")
            .stdout("build/cmake-prep.log")
            .stderr_to_stdout()
            .run()
            .expect("!cmake");

        let _ = cmd!(
            "cmake",
            "--build",
            ".",
            "--target",
            "marketmaker-testnet-lib"
        ).dir("build")
        .stdout("build/cmake-testnet.log")
        .stderr_to_stdout()
        .run()
        .expect("!cmake");

        let _ = cmd!(
            "cmake",
            "--build",
            ".",
            "--target",
            "marketmaker-mainnet-lib"
        ).dir("build")
        .stdout("build/cmake-mainnet.log")
        .stderr_to_stdout()
        .run()
        .expect("!cmake");
    }

    // The MM1 library.

    let mm_flavor = env::var("MM_FLAVOR");
    let mm1lib = match mm_flavor {
        Ok(ref f) if f == "mainnet" => "marketmaker-mainnet-lib",
        Ok(ref f) if f == "testnet" => "marketmaker-testnet-lib",
        _ => "marketmaker-mainnet-lib",
    };
    println!("cargo:rustc-link-search=native=./build/iguana/exchanges");
    println!("cargo:rustc-link-lib=static={}", mm1lib);

    // Libraries need for MM1.

    let mm1etlib = match mm_flavor {
        Ok(ref f) if f == "mainnet" => "etomiclib-mainnet",
        Ok(ref f) if f == "testnet" => "etomiclib-testnet",
        _ => "etomiclib-mainnet",
    };
    println!("cargo:rustc-link-search=native=./build/iguana/exchanges/etomicswap");
    println!("cargo:rustc-link-lib=static={}", mm1etlib);

    println!("cargo:rustc-link-search=native=./build/crypto777");
    println!("cargo:rustc-link-lib=static=libcrypto777");

    println!("cargo:rustc-link-search=native=./build/crypto777/jpeg");
    println!("cargo:rustc-link-lib=static=libjpeg");

    println!("cargo:rustc-link-search=native=./build/iguana/secp256k1");
    println!("cargo:rustc-link-lib=static=libsecp256k1");

    if cfg!(windows) {
        // TODO: Should fix the Git repository and the Windows scripts to use one folder instead of three
        //       in order to avoid outdated library versions and mismatches.
        println!("cargo:rustc-link-search=native=./OSlibs/win");
        println!("cargo:rustc-link-search=native=./OSlibs/win/x64");
        println!("cargo:rustc-link-search=native=./OSlibs/win/x64/release");
        // When building locally with CMake 3.12.0 on Windows the artefacts are created in the "Debug" folders:
        println!("cargo:rustc-link-search=native=./build/iguana/exchanges/Debug");
        println!("cargo:rustc-link-search=native=./build/iguana/exchanges/etomicswap/Debug");
        println!("cargo:rustc-link-search=native=./build/crypto777/Debug");
        println!("cargo:rustc-link-search=native=./build/crypto777/jpeg/Debug");
        println!("cargo:rustc-link-search=native=./build/iguana/secp256k1/Debug");
    }

    println!("cargo:rustc-link-search=native=./build/nanomsg-build");
    println!("cargo:rustc-link-lib=static=nanomsg");

    println!(
        "cargo:rustc-link-lib={}",
        if cfg!(windows) { "libcurl" } else { "curl" }
    );
    if !cfg!(windows) {
        println!("cargo:rustc-link-lib=crypto");
    }
}

fn main() {
    let mm_version = mm_version();
    build_c_code(&mm_version);
    generate_bindings();
}
