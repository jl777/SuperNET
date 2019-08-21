#!/bin/dash
# Run with `dash js/wasm-build.sh`.
set -ex
cargo build --target=wasm32-unknown-unknown --release
ln -f target/wasm32-unknown-unknown/release/mm2.wasm js/mm2.wasm
