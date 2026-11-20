#pragma once
#include <cstddef>
#include <cstdint>

inline uint32_t ct_is_zero(uint32_t x)
{
    uint32_t nonzero = (x | (0u - x)) >> 31;
    return 0u - (1u ^ nonzero);
}

inline uint32_t ct_eq(uint32_t a, uint32_t b)
{
    return ct_is_zero(a ^ b);
}

inline uint32_t ct_lt(uint32_t a, uint32_t b)
{
    return 0u - ((a - b) >> 31);
}

inline uint32_t ct_select(uint32_t mask, uint32_t a, uint32_t b)
{
    return (a & mask) | (b & ~mask);
}

inline void secure_zero(void* p, size_t n)
{
    volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
    while (n--) {
        *q++ = 0;
    }
}
