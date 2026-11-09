#pragma once
#include <cstddef>
#include <cstdint>
void random_bytes(uint8_t* buf, size_t len);   // CSPRNG ОС (getrandom)
