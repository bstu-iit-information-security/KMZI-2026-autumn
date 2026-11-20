add_library(ed25519_core STATIC
    src/field.cpp
    src/edwards.cpp
    src/eddsa.cpp
    src/sha512.cpp
)

target_include_directories(ed25519_core PUBLIC include)

add_executable(backend src/main.cpp)
target_link_libraries(backend PRIVATE ed25519_core)