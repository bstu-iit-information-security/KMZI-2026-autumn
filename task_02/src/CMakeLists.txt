cmake_minimum_required(VERSION 3.20)
project(KMZIlab2)

set(CMAKE_CXX_STANDARD 17)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")

find_package(Boost REQUIRED)

add_executable(KMZIlab2 main.cpp)

target_include_directories(KMZIlab2 PRIVATE ${Boost_INCLUDE_DIRS})