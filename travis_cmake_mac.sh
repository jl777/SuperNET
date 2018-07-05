#!/bin/bash
wget https://cmake.org/files/v3.12/cmake-3.12.0-rc2-Darwin-x86_64.dmg
sudo hdiutil attach cmake-3.12.0-rc2-Darwin-x86_64.dmg
sudo installer -package /Volumes/cmake-3.12.0-rc2-Darwin-x86_64/cmake-3.12.0-rc2-Darwin-x86_64.pkg -target /
sudo hdiutil detach /Volumes/cmake-3.12.0-rc2-Darwin-x86_64
cmake --version