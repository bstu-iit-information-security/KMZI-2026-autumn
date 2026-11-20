cmake_minimum_required(VERSION 3.10)
project(lab1_gcm_aes_variant11 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(main
    ./galois.cpp
    ./aes128.cpp
    ./gcm.cpp
    ./main.cpp
)
