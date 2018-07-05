#!/bin/bash
brew uninstall cmake --force
wget https://cmake.org/files/v3.12/cmake-3.12.0-rc2-Darwin-x86_64.dmg
hdiutil convert -quiet cmake-3.12.0-rc2-Darwin-x86_64.dmg -format UDTO -o bar
hdiutil attach -quiet -nobrowse -noverify -noautoopen -mountpoint right_here bar.cdr
ls right_here
sudo installer -package right_here/cmake-3.12.0-rc2-Darwin-x86_64/cmake-3.12.0-rc2-Darwin-x86_64.pkg -target /
sysctl -n hw.physicalcpu
which cmake
cmake --version