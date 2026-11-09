cmake_minimum_required(VERSION 3.25)
project(belt_gcm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(crypto)
add_subdirectory(demo)
add_subdirectory(test)


add_executable(${PROJECT_NAME} main.cpp)


target_link_libraries(${PROJECT_NAME} PRIVATE
    gf256
    belt
    gcm
    demo
    test
)