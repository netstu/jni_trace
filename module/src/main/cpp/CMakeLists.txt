cmake_minimum_required(VERSION 3.28.0+)
project("jni_trace")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/${ANDROID_ABI}")

find_library(log-lib log)

add_subdirectory(./base)
add_subdirectory(./global)
add_subdirectory(third/log2file)
add_subdirectory(./third)

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
        dobby
        libbase
        libutils
        libbyopen
        libjson
        global
        log2file
        ${log-lib}
)