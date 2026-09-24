cmake_minimum_required(VERSION 3.10)
project(lab1_gcm_aes_variant11 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(lab1
    src/galois.cpp
    src/aes128.cpp
    src/gcm.cpp
    src/main.cpp
)
