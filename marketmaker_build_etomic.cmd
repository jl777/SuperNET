@echo off
rem (c) Decker

echo Windows version and architecture:
ver
wmic os get osarchitecture

echo [#1] Install Rust, build nanomsg, curl and pthreads ...
call marketmaker_build_depends.cmd

echo [#2] Prepare the build.
mkdir build
cd build
cmake .. -DMM_VERSION="%APPVEYOR_BUILD_VERSION%"

echo [#3] Build the marketmaker-mainnet library.

cmake --build . --target marketmaker-mainnet-lib
cd ..

echo [#4] Build and test the MM2.

cargo test
cargo build
