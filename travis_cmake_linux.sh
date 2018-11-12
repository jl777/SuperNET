#!/bin/bash
sudo rm -rf /usr/local/cmake-3.9.2 && sudo rm -rf /usr/local/cmake
wget https://cmake.org/files/v3.12/cmake-3.12.0-rc2-Linux-x86_64.sh
chmod +x cmake-3.12.0-rc2-Linux-x86_64.sh
sudo ./cmake-3.12.0-rc2-Linux-x86_64.sh --skip-license --exclude-subdir --prefix=/usr/local