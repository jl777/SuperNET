#!/bin/bash
brew uninstall cmake --force
wget https://cmake.org/files/v3.12/cmake-3.12.0-rc2-Darwin-x86_64.tar.gz
tar -xzf cmake-3.12.0-rc2-Darwin-x86_64.tar.gz
cp -r cmake-3.12.0-rc2-Darwin-x86_64/CMake.app/Contents/bin/* /usr/local/bin/
cp -r cmake-3.12.0-rc2-Darwin-x86_64/CMake.app/Contents/share/* /usr/local/share/