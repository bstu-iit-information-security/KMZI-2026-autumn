cmake_minimum_required(VERSION 3.10)
project(lab1 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(lab1 main.cpp gf256.hpp belt.hpp gcm.hpp)

if(MSVC)
    target_compile_options(lab1 PRIVATE /W4)
else()
    target_compile_options(lab1 PRIVATE -Wall -Wextra)
endif()

enable_testing()
add_test(NAME lab1_all_tests COMMAND lab1)
