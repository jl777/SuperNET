#!/bin/bash
brew reinstall --HEAD cmake
sysctl -n hw.physicalcpu
which cmake
cmake --version