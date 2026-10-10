cmake_minimum_required(VERSION 3.20)
project(kmzilab3 CXX)

set(CMAKE_CXX_STANDARD 17)
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")
endif()

find_package(Boost REQUIRED)

add_executable(kmzilab3 main.cpp)

target_link_libraries(kmzilab3 PRIVATE Boost::boost)