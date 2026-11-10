cmake_minimum_required(VERSION 3.10)
project(rsa_lab2_variant8 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
# -O2: достаточно для замеров; никаких -ffast-math и т.п. (ломают constant-time)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

# --- Библиотека больших чисел GMP (разрешена ТОЛЬКО для арифметики) ---------
# Ищем в системе (apt install libgmp-dev) или в ./third_party/gmp
find_path(GMP_INCLUDE_DIR gmpxx.h HINTS ${CMAKE_SOURCE_DIR}/third_party/gmp/include)
find_library(GMP_LIB   NAMES gmp   HINTS ${CMAKE_SOURCE_DIR}/third_party/gmp/lib)
find_library(GMPXX_LIB NAMES gmpxx HINTS ${CMAKE_SOURCE_DIR}/third_party/gmp/lib)
if(NOT GMP_INCLUDE_DIR OR NOT GMP_LIB OR NOT GMPXX_LIB)
  message(FATAL_ERROR "GMP не найден. Установите: sudo apt install libgmp-dev")
endif()

# --- Модуль 1: теория чисел (Евклид, Joye-Tun, Миллер-Рабин) ----------------
add_library(mod1_numtheory STATIC src/bigint_math.cpp)
target_include_directories(mod1_numtheory PUBLIC src ${GMP_INCLUDE_DIR})
target_link_libraries(mod1_numtheory PUBLIC ${GMPXX_LIB} ${GMP_LIB})

# --- Модуль 2: ядро RSA + CRT (Гарнер) ---------------------------------------
add_library(mod2_rsa_crt STATIC src/rsa_core.cpp)
target_link_libraries(mod2_rsa_crt PUBLIC mod1_numtheory)

# --- Модуль 3: OAEP + SHA-256 + constant-time (БЕЗ зависимости от GMP) -------
add_library(mod3_oaep STATIC src/sha256.cpp src/oaep.cpp)
target_include_directories(mod3_oaep PUBLIC src)

# --- Склейка модулей 2 и 3 ----------------------------------------------------
add_library(rsa_oaep STATIC src/rsa_oaep.cpp)
target_link_libraries(rsa_oaep PUBLIC mod2_rsa_crt mod3_oaep)

# --- Программы ---------------------------------------------------------------
add_executable(rsa_tests tests/tests.cpp)
target_link_libraries(rsa_tests PRIVATE rsa_oaep)

add_executable(rsa_bench tests/bench.cpp)
target_link_libraries(rsa_bench PRIVATE rsa_oaep)

enable_testing()
add_test(NAME rsa_tests COMMAND rsa_tests)
