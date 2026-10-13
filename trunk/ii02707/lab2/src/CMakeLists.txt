cmake_minimum_required(VERSION 3.16)
project(RSA_OAEP_Blinding CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# OpenSSL используется ТОЛЬКО как BigInt-библиотека (арифметика больших чисел).
# Вся криптография (SHA3, OAEP, RSA, Blinding) реализована вручную.
find_package(OpenSSL REQUIRED)

add_executable(rsa_lab
    main.cpp
    bigint.cpp
    sha3.cpp
    rsa_math.cpp
    rsa_core.cpp
    oaep.cpp
)

target_link_libraries(rsa_lab PRIVATE OpenSSL::Crypto)
target_compile_options(rsa_lab PRIVATE -O2 -Wall -Wextra -Wpedantic)