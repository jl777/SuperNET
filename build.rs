// The script here will translate some of the C headers necessary for the gradual Rust port into the corresponding Rust files.
// Going to take the *whitelisting* approach, converting just the necessary definitions, in order to keep the builds fast.

// Bindgen requirements: https://rust-lang-nursery.github.io/rust-bindgen/requirements.html
//              Windows: https://github.com/rust-lang-nursery/rustup.rs/issues/1003#issuecomment-289825927
// On build.rs: https://doc.rust-lang.org/cargo/reference/build-scripts.html

extern crate bindgen;
extern crate gstuff;

use gstuff::last_modified_sec;
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
fn mm_version() {
    if option_env!("MM_VERSION").is_some() {
        return; // The variable is already there.
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
}

fn main() {
    generate_bindings();
    mm_version();
}
