cmake_minimum_required(VERSION 3.5.1)
include("cmake/HunterGate.cmake")
HunterGate(
        URL "https://github.com/ruslo/hunter/archive/v0.19.173.tar.gz"
        SHA1 "750fb1d621af971fad6f303356b13017ad9f5e15"
        LOCAL
)
project(SuperNET)
include_directories("${CMAKE_SOURCE_DIR}")
add_subdirectory(cpp-ethereum)
add_subdirectory(iguana/exchanges)
add_subdirectory(iguana/secp256k1)
add_subdirectory(crypto777)
add_subdirectory(crypto777/jpeg)