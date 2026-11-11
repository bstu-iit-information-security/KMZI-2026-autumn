add_executable(frontend src/main.cpp)
target_link_libraries(frontend PRIVATE ed25519_core)