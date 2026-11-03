#include "gf8.hpp"

Gf8::Gf8(uint16_t poly) : poly_(poly) {}

uint8_t Gf8::mul_nibble(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 4; ++i) {
        const uint8_t bit = static_cast<uint8_t>((b >> i) & 1u);
        const uint8_t mask = static_cast<uint8_t>(0u - bit);
        result ^= static_cast<uint8_t>(a << i) & mask;
    }
    return result;
}

uint8_t Gf8::reduce(uint16_t value) const {
    for (int degree = 14; degree >= 8; --degree) {
        const uint16_t bit = static_cast<uint16_t>((value >> degree) & 1u);
        const uint16_t mask = static_cast<uint16_t>(0u - bit);
        value ^= static_cast<uint16_t>(poly_ << (degree - 8)) & mask;
    }
    return static_cast<uint8_t>(value);
}

uint8_t Gf8::multiply(uint8_t a, uint8_t b) const {
    const uint8_t a0 = static_cast<uint8_t>(a & 0x0F);
    const uint8_t a1 = static_cast<uint8_t>(a >> 4);
    const uint8_t b0 = static_cast<uint8_t>(b & 0x0F);
    const uint8_t b1 = static_cast<uint8_t>(b >> 4);

    const uint8_t p0 = mul_nibble(a0, b0);
    const uint8_t p2 = mul_nibble(a1, b1);
    const uint8_t p1 = mul_nibble(static_cast<uint8_t>(a0 ^ a1), static_cast<uint8_t>(b0 ^ b1));

    const uint16_t wide = static_cast<uint16_t>(
        p0 ^
        (static_cast<uint16_t>(p0 ^ p1 ^ p2) << 4) ^
        (static_cast<uint16_t>(p2) << 8));
    return reduce(wide);
}

uint8_t Gf8::xtime(uint8_t a) const {
    const uint8_t mask = static_cast<uint8_t>(0u - (a >> 7));
    return static_cast<uint8_t>((a << 1) ^ (mask & static_cast<uint8_t>(poly_)));
}

uint8_t Gf8::inverse(uint8_t a) const {
    uint8_t square = multiply(a, a);
    uint8_t result = square;
    for (int i = 0; i < 6; ++i) {
        square = multiply(square, square);
        result = multiply(result, square);
    }
    return result;
}

uint8_t Gf8::affine(uint8_t value) {
    uint8_t result = value;
    for (int shift = 1; shift <= 4; ++shift) {
        result ^= static_cast<uint8_t>((value << shift) | (value >> (8 - shift)));
    }
    return static_cast<uint8_t>(result ^ 0x63);
}

void Gf8::fill_sbox(uint8_t sbox[256]) const {
    for (int i = 0; i < 256; ++i) {
        sbox[i] = affine(inverse(static_cast<uint8_t>(i)));
    }
}
