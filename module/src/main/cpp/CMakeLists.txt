cmake_minimum_required(VERSION 3.28.0+)
project("jni_trace")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/${ANDROID_ABI}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}   -Wc99-designator")
if (${CMAKE_ANDROID_ARCH_ABI} STREQUAL "arm64-v8a")
        set(LINK_DIR ${PROJECT_SOURCE_DIR}/../../../libs/arm64-v8a)
elseif (${CMAKE_ANDROID_ARCH_ABI} STREQUAL "armeabi-v7a")
        set(LINK_DIR ${PROJECT_SOURCE_DIR}/../../../libs/armeabi-v7a)
elseif (${CMAKE_ANDROID_ARCH_ABI} STREQUAL "x86_64")
        set(LINK_DIR ${PROJECT_SOURCE_DIR}/../../../libs/x86_64)
elseif (${CMAKE_ANDROID_ARCH_ABI} STREQUAL "x86")
        set(LINK_DIR ${PROJECT_SOURCE_DIR}/../../../libs/x86)
endif ()
find_library(log-lib log)

add_subdirectory(./base)
add_subdirectory(./global)
add_subdirectory(third/log2file)
add_subdirectory(./third)
#add_subdirectory(./libcxx)

file(GLOB analyse_src
        "*.h"
        "*.hpp"
        "*.cpp"

        "jni_trace/*.cpp"
        "jni_trace/*.h"
        )

add_library(
        analyse
        SHARED
        ${analyse_src}
)

target_link_libraries(
        analyse
#        ${LINK_DIR}/libcxx.a
#        libcxx
        dobby
        libbase
        libutils
        libbyopen
        libjson
        global
        log2file
        ${log-lib}
)