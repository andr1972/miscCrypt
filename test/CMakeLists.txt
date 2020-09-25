cmake_minimum_required(VERSION 3.17)
project(test)

set(CMAKE_CXX_STANDARD 14)

add_executable(test main.cpp
        ../hashes/DCPh_haval.cpp
        ../hashes/DCPh_md4.cpp
        ../hashes/DCPh_md5.cpp
        ../hashes/DCPh_ripemd128.cpp
        ../hashes/DCPh_ripemd160.cpp
        ../hashes/DCPh_sha1_160.cpp
        ../hashes/DCPh_sha2_256.cpp
        ../hashes/DCPh_sha3.cpp
        ../ciphers/DCPc_rijndael.cpp
        ../ciphers/DCPc_blowfish.cpp
        ../ciphers/DCPc_twofish.cpp
        ../ciphers/DCPc_serpent.cpp
        ../ciphers/DCP_cipher.cpp
        ../ciphers/DCP_blockcipher.cpp
        ../ciphers/DCP_blockcipher64.cpp
        ../ciphers/DCP_blockcipher128.cpp
            ../util/Base64.cpp ../util/Util.cpp
        ../Argon2/argon2-core.cpp
        ../Argon2/argon2.cpp
        ../Argon2/argon2-opt-core.cpp
        ../Blake2/blake2b.cpp)
target_include_directories(test PRIVATE ../util ../hashes ../ciphers)

target_link_libraries(test pthread)