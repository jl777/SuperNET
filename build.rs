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

fn generate_bindings() {
    let _ = fs::create_dir("mm2src/c_headers");

    // NB: curve25519.h and cJSON.h are needed to parse LP_include.h.
    bindgen(
        vec![
            "includes/curve25519.h".into(),
            "includes/cJSON.h".into(),
            "iguana/exchanges/LP_include.h".into(),
        ],
        "mm2src/c_headers/LP_include.rs",
        [
            "cJSON_Parse",
            "cJSON_GetErrorPtr",
            "cJSON_Delete",
            "LP_NXT_redeems",
        ]
            .iter(),
        ["_bits256", "cJSON"].iter(),
        ["GLOBAL_DBDIR", "DOCKERFLAG"].iter(),
    );

    bindgen(
        vec!["crypto777/OS_portable.h".into()],
        "mm2src/c_headers/OS_portable.rs",
        [
            "OS_init",
            "OS_randombytes",
            "OS_ensure_directory",
            "OS_compatible_path",
            "calc_ipbits",
        ]
            .iter(),
        empty(),
        empty(),
    );
    bindgen(
        vec!["crypto777/nanosrc/nn.h".into()],
        "mm2src/c_headers/nn.rs",
        ["nn_socket", "nn_connect", "nn_recv", "nn_freemsg"].iter(),
        empty(),
        ["AF_SP", "NN_PAIR"].iter(),
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
    let version = if let Ok(mut file) = fs::File::open("MM_VERSION") {
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

/// Build helper C code.
///
/// I think "git clone ... && cargo build" should be enough to start hacking on the Rust code.
///
/// For now we're building the Structured Exception Handling code here,
/// but in the future we might subsume the rest of the C build under build.rs.
fn build_c_code(mm_version: &str) {
    // Link in the Windows-specific crash handling code.

    if cfg!(windows) {
        let lm_build_rs = unwrap!(last_modified_sec(&"build.rs"), "Can't stat build.rs");
        let lm_seh = unwrap!(last_modified_sec(&"mm2src/seh.c"), "Can't stat seh.c");
        let out_dir = unwrap!(env::var("OUT_DIR"), "!OUT_DIR");
        let lib_path = Path::new(&out_dir).join("libseh.a");
        let lm_lib = last_modified_sec(&lib_path).unwrap_or(0.);
        if lm_build_rs.max(lm_seh) >= lm_lib - SLIDE {
            cc::Build::new()
                .file("mm2src/seh.c")
                .warnings(true)
                .compile("seh");
        }
        println!("cargo:rustc-link-lib=static=seh");
        println!("cargo:rustc-link-search=native={}", out_dir);
    }

    // The MM1 library.

    let _ = fs::create_dir("build");

    // NB: With "duct 0.11.0" the `let _` variable binding is necessary in order for the build not to fall detached into background.
    let mut cmake_prep_args: Vec<String> = Vec::new();
    if cfg!(windows) {
        // To flush the build problems early we explicitly specify that we want a 64-bit MSVC build and not a GNU or 32-bit one.
        cmake_prep_args.push("-G".into());
        cmake_prep_args.push("Visual Studio 15 2017 Win64".into());
    }
    if env::var_os("CARGO_FEATURE_ETOMIC").is_some() {
        // cargo build -vv --features etomic
        cmake_prep_args.push("-DETOMIC=ON".into());
    }
    cmake_prep_args.push(format!("-DMM_VERSION={}", mm_version));
    cmake_prep_args.push("..".into());
    eprintln!("$ cmake{}", show_args(&cmake_prep_args));
    let _ = unwrap!(
        cmd("cmake", cmake_prep_args).dir("build")
        .stdout_to_stderr()  // NB: stderr is visible through "cargo build -vv".
        .run(),
        "!cmake"
    );

    let mut cmake_args: Vec<String> = vec![
        "--build".into(),
        ".".into(),
        "--target".into(),
        "marketmaker-mainnet-lib".into(),
    ];
    if !cfg!(windows) {
        // Doesn't currently work on AppVeyor.
        cmake_args.push("-j".into());
        cmake_args.push(format!("{}", num_cpus::get()));
    }
    eprintln!("$ cmake{}", show_args(&cmake_args));
    let _ = unwrap!(
        cmd("cmake", cmake_args).dir("build")
        .stdout_to_stderr()  // NB: stderr is visible through "cargo build -vv".
        .run(),
        "!cmake"
    );

    println!("cargo:rustc-link-lib=static=marketmaker-mainnet-lib");

    // Link in the libraries needed for MM1.

    if env::var_os("CARGO_FEATURE_ETOMIC").is_some() {
        println!("cargo:rustc-link-lib=static=etomiclib-mainnet");
    }
    println!("cargo:rustc-link-lib=static=libcrypto777");
    println!("cargo:rustc-link-lib=static=libjpeg");
    println!("cargo:rustc-link-lib=static=libsecp256k1");

    if cfg!(windows) {
        println!("cargo:rustc-link-search=native=./x64");
        // When building locally with CMake 3.12.0 on Windows the artefacts are created in the "Debug" folders:
        println!("cargo:rustc-link-search=native=./build/iguana/exchanges/Debug");
        println!("cargo:rustc-link-search=native=./build/iguana/exchanges/etomicswap/Debug");
        println!("cargo:rustc-link-search=native=./build/crypto777/Debug");
        println!("cargo:rustc-link-search=native=./build/crypto777/jpeg/Debug");
        println!("cargo:rustc-link-search=native=./build/iguana/secp256k1/Debug");
    // https://stackoverflow.com/a/10234077/257568
    //println!(r"cargo:rustc-link-search=native=c:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\Tools\MSVC\14.14.26428\lib\x64");
    } else {
        println!("cargo:rustc-link-search=native=./build/iguana/exchanges");
        println!("cargo:rustc-link-search=native=./build/iguana/exchanges/etomicswap");
        println!("cargo:rustc-link-search=native=./build/crypto777");
        println!("cargo:rustc-link-search=native=./build/crypto777/jpeg");
        println!("cargo:rustc-link-search=native=./build/iguana/secp256k1");
        println!("cargo:rustc-link-search=native=./build/nanomsg-build");
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
            fs::copy("x64/pthreadVC2.dll", "target/debug/pthreadVC2.dll"),
            "Can't copy pthreadVC2.dll"
        );
        unwrap!(
            fs::copy("x64/libcurl.dll", "target/debug/libcurl.dll"),
            "Can't copy libcurl.dll"
        );
    } else {
        println!("cargo:rustc-link-lib=crypto");
        println!("cargo:rustc-link-lib=static=nanomsg");
    }
}

fn main() {
    // Rebuild when we work with C files.
    println!("rerun-if-changed=iguana/exchanges/etomicswap");
    println!("rerun-if-changed=iguana/exchanges/etomicswap/etomiclib.h");
    println!("rerun-if-changed=iguana/exchanges");
    println!("rerun-if-changed=iguana/secp256k1");
    println!("rerun-if-changed=crypto777");
    println!("rerun-if-changed=crypto777/jpeg");
    println!("rerun-if-changed=OSlibs/win");
    println!("rerun-if-changed=CMakeLists.txt");

    // Rebuild when the build folder is removed.
    // NB: This works NP before a Rust build, but doesn't work when Cargo decides to skip the build altogether.
    //     So to force a full rebuild we might need an extra touch: `rm -rf build && touch mm2src/mm2.rs`.
    println!("rerun-if-changed=build");

    // Rebuild when we change certain features.
    println!("rerun-if-env-changed=CARGO_FEATURE_ETOMIC");
    println!("rerun-if-env-changed=CARGO_FEATURE_NOP");

    // Rebuild if version changes.
    println!("rerun-if-changed=MM_VERSION");
    println!("rerun-if-env-changed=MM_VERSION");

    // Used with mm2-nop.rs in order to separately the dependencies build from the MM1 C build.
    if env::var_os("CARGO_FEATURE_NOP").is_some() {
        return;
    }

    windows_requirements();
    let mm_version = mm_version();
    build_c_code(&mm_version);
    generate_bindings();
}
