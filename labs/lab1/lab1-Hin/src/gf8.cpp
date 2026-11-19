#include "gf8.hpp"

Gf8::Gf8(uint16_t poly) : poly_(poly) {}

uint8_t Gf8::reduce(uint16_t value) const {
    for (int degree = 14; degree >= 8; --degree) {
        const uint16_t bit = static_cast<uint16_t>((value >> degree) & 1u);
        const uint16_t mask = static_cast<uint16_t>(0u - bit);
        value ^= static_cast<uint16_t>(poly_ << (degree - 8)) & mask;
    }
    return static_cast<uint8_t>(value);
}

uint8_t Gf8::multiply(uint8_t a, uint8_t b) const {
    uint16_t product = 0;
    for (int i = 0; i < 8; ++i) {
        const uint16_t mask = static_cast<uint16_t>(0u - ((b >> i) & 1u));
        product ^= static_cast<uint16_t>(static_cast<uint16_t>(a) << i) & mask;
    }
    return reduce(product);
}

uint8_t Gf8::xtime(uint8_t a) const {
    const uint8_t mask = static_cast<uint8_t>(0u - (a >> 7));
    return static_cast<uint8_t>((a << 1) ^ (mask & static_cast<uint8_t>(poly_)));
}

uint8_t Gf8::inverse(uint8_t a) const {
    const uint8_t a2 = multiply(a, a);
    const uint8_t a4 = multiply(a2, a2);
    const uint8_t a8 = multiply(a4, a4);
    const uint8_t a16 = multiply(a8, a8);
    const uint8_t a32 = multiply(a16, a16);
    const uint8_t a64 = multiply(a32, a32);
    const uint8_t a128 = multiply(a64, a64);

    uint8_t result = a128;
    result = multiply(result, a64);
    result = multiply(result, a32);
    result = multiply(result, a16);
    result = multiply(result, a8);
    result = multiply(result, a4);
    result = multiply(result, a2);
    return result;
}

uint8_t Gf8::affine(uint8_t value) {
    uint8_t result = value;
    for (int shift = 1; shift <= 4; ++shift) {
        result ^= static_cast<uint8_t>((value << shift) | (value >> (8 - shift)));
    }
    return static_cast<uint8_t>(result ^ 0x63);
}

uint8_t Gf8::inv_affine(uint8_t value) {
    const auto rotl = [](uint8_t v, int shift) {
        return static_cast<uint8_t>((v << shift) | (v >> (8 - shift)));
    };
    return static_cast<uint8_t>(rotl(value, 1) ^ rotl(value, 3) ^ rotl(value, 6) ^ 0x05);
}

uint8_t Gf8::sub_byte(uint8_t value) const {
    return affine(inverse(value));
}

uint8_t Gf8::inv_sub_byte(uint8_t value) const {
    return inverse(inv_affine(value));
}

void Gf8::fill_sbox(uint8_t sbox[256]) const {
    for (int i = 0; i < 256; ++i) {
        sbox[i] = sub_byte(static_cast<uint8_t>(i));
    }
}
