#!/bin/bash
which cmake
brew uninstall cmake --force
brew cleanup
which cmake
sysctl -n hw.physicalcpu