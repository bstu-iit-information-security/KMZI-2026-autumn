cmake_minimum_required(VERSION 3.25)
project(lab1_ii02707_src)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
)

add_subdirectory(belt)
add_subdirectory(galois)

add_executable(${PROJECT_NAME} ${PROJECT_SOURCES})

target_link_libraries(${PROJECT_NAME} PRIVATE
   galois
)