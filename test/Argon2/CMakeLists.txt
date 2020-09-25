cmake_minimum_required(VERSION 3.17)
project(Argon2)

set(CMAKE_CXX_STANDARD 14)

add_executable(Argon2 main.cpp main
        ../../Argon2/argon2-core.cpp
        ../../Argon2/argon2.cpp
        ../../Argon2/argon2-opt-core.cpp
        ../../Blake2/blake2b.cpp)

target_link_libraries(Argon2 pthread)