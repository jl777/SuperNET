// Do-nothing binary.
// 
// We use it in order to log the C / CMake parts of the build in the CIs
// but without overflowing the CI logs with the verbose dependency build logs.
// 
// In the future this might be implemented directly by Cargo,
// cf. https://github.com/rust-lang/cargo/issues/2644#issuecomment-411719921

fn main() {}