cmake_minimum_required(VERSION 3.10)
project(RsaLab CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(rsa_lab main.cpp)

target_compile_options(rsa_lab PRIVATE -Wall -Wextra)
