#include "rng.hpp"
#include <cstdio>
#include <random>

void random_bytes(uint8_t* buf, size_t n)
{
    FILE* f = std::fopen("/dev/urandom", "rb");
    if (f) {
        size_t got = std::fread(buf, 1, n, f);
        std::fclose(f);
        if (got == n) {
            return;
        }
    }
    std::random_device rd;
    for (size_t i = 0; i < n; i++) {
        buf[i] = static_cast<uint8_t>(rd() & 0xFF);
    }
}
