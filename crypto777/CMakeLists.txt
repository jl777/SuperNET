file(GLOB sources "*.c")
file(GLOB headers "*.h")
add_library(libcrypto777 ${sources} ${headers})
target_link_libraries(libcrypto777 PUBLIC curl)