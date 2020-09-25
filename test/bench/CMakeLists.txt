cmake_minimum_required(VERSION 3.17)
project(bench)

set(CMAKE_CXX_STANDARD 14)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    link_directories(../../cmake-build-debug)
else ()
    link_directories(../../cmake-build-release)
endif ()


add_executable(bench main.cpp)
target_include_directories(bench PRIVATE ../../util ../../hashes ../../ciphers)

target_link_libraries(bench miscCrypt pthread)