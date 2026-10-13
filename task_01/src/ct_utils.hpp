#pragma once

#include <cstddef>
#include <cstdint>

namespace ct {

inline uint32_t rotl32(uint32_t x, unsigned n) {
    n &= 31u;
    return (x << n) | (x >> ((32u - n) & 31u));
}

inline uint32_t rotr32(uint32_t x, unsigned n) {
    n &= 31u;
    return (x >> n) | (x << ((32u - n) & 31u));
}

inline uint8_t mask8(uint8_t bit) {
    return static_cast<uint8_t>(0u - static_cast<unsigned>(bit & 1u));
}

inline bool equal(const uint8_t* a, const uint8_t* b, std::size_t n) {
    uint8_t delta = 0;
    for (std::size_t i = 0; i < n; ++i) {
        delta = static_cast<uint8_t>(delta | (a[i] ^ b[i]));
    }
    return delta == 0;
}

}
