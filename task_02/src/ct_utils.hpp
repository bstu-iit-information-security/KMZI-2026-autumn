// Мелкие constant-time помощники: всё на масках, без if / ?: по секретным данным.
// Маска = 0xFFFFFFFF ("истина") или 0x00000000 ("ложь").
#pragma once
#include <cstddef>
#include <cstdint>

namespace ct {

// Барьер: не даёт компилятору "умно" превратить маску обратно в ветвление.
inline uint32_t barrier(uint32_t x) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" : "+r"(x));
#endif
    return x;
}

inline uint32_t nonzero_mask(uint32_t x) {          // x != 0  ->  всё единицы
    return barrier(0u - ((x | (0u - x)) >> 31));
}
inline uint32_t zero_mask(uint32_t x) { return ~nonzero_mask(x); }
inline uint32_t eq_mask(uint32_t a, uint32_t b) { return zero_mask(a ^ b); }

// a < b, при условии что a, b < 2^31
inline uint32_t lt_mask(uint32_t a, uint32_t b) { return barrier(0u - ((a - b) >> 31)); }

// mask ? a : b
inline uint32_t select(uint32_t mask, uint32_t a, uint32_t b) {
    return (mask & a) | (~mask & b);
}

// Затирание секретов (компилятор не имеет права выкинуть).
inline void secure_zero(void* p, size_t n) {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) v[i] = 0;
}

}  // namespace ct
