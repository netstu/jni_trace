cmake_minimum_required(VERSION 3.28.0+)
project("third")
enable_language(ASM)

file(GLOB utils_src
        "utils/*.h"
        "utils/*.cpp"
        "utils/*.c"
        "utils/*.asm"
)

add_library(libutils
        STATIC
        ${utils_src})

set(DobbyHome "./dobby")
#set(GENERATE_SHARED OFF)
#set(DOBBY_DEBUG OFF)
add_subdirectory(${DobbyHome} dobby)

file(GLOB byopen_src
        "byopen/*.h"
        "byopen/*.cpp"
        "byopen/*.c")

add_library(libbyopen
        STATIC
        ${byopen_src})
