file(GLOB sources "*.c")
file(GLOB headers "*.h")
add_library(libjpeg STATIC ${sources} ${headers})
target_sources(libjpeg PRIVATE "unix/jmemname.c")
