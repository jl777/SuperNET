include_directories(${CMAKE_CURRENT_SOURCE_DIR})
file(GLOB sources "src/secp256k1.c")
file(GLOB headers "src/*.h")
add_definitions(-DHAVE_CONFIG_H)

if (DEFINED ETOMIC)
    add_definitions(-DEXTERNAL_SECP256)
endif()

add_library(libsecp256k1 STATIC ${sources} ${headers})