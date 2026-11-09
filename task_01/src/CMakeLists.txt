cmake_minimum_required(VERSION 3.16)
project(lab1_belt_gcm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

add_executable(lab1
        src/main.cpp
        src/galois_field.cpp
        src/galois_field.hpp
        src/belt.cpp
        src/belt.hpp
        src/gcm.cpp
        src/gcm.hpp
        src/ct_utils.hpp)

target_include_directories(lab1 PRIVATE src)

if(MSVC)
    target_compile_options(lab1 PRIVATE /W4)
else()
    target_compile_options(lab1 PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion)
endif()
