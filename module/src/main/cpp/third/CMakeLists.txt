cmake_minimum_required(VERSION 3.28.0+)
project("third")

file(GLOB utils_src
        "utils/*.h"
        "utils/*.cpp"
        "utils/*.c")

add_library(libutils
        STATIC
        ${utils_src})

file(GLOB json_src
        "json/*.h"
        "json/*.cpp"
        "json/*.c")

add_library(libjson
        STATIC
        ${json_src})


#add_library(
#        libcxx
#        SHARED
#        IMPORTED
#)

#set_target_properties(libcxx
#        PROPERTIES IMPORTED_LOCATION
#        ${LINK_DIR}/libcxx.a)

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
