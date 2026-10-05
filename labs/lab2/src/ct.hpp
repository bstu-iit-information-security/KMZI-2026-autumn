// Constant-time примитивы: маски вместо ветвлений. Все значения < 2^31.
#pragma once
#include <cstddef>
#include <cstdint>

namespace ct {

// 0xFFFFFFFF если a == b, иначе 0
inline uint32_t eq_mask(uint32_t a, uint32_t b) {
    uint32_t x = a ^ b;
    return ((x | (0u - x)) >> 31) - 1u;
}
// 0xFFFFFFFF если x != 0, иначе 0
inline uint32_t nonzero_mask(uint32_t x) { return ~eq_mask(x, 0u); }
// 0xFFFFFFFF если a < b (a,b < 2^31), иначе 0
inline uint32_t lt_mask(uint32_t a, uint32_t b) { return 0u - ((a - b) >> 31); }
// mask ? a : b
inline uint32_t select(uint32_t mask, uint32_t a, uint32_t b) { return (mask & a) | (~mask & b); }
inline uint64_t select64(uint64_t mask, uint64_t a, uint64_t b) { return (mask & a) | (~mask & b); }

// Гарантированное затирание секретов (не вырезается оптимизатором)
inline void secure_zero(void* p, size_t n) {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) v[i] = 0;
}

} // namespace ct
