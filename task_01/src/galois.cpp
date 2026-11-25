#include "galois.h"

GaloisField::GaloisField(uint16_t modulus) : modulus_(modulus) {}

uint16_t GaloisField::modulus() const {
    return modulus_;
}

uint8_t GaloisField::add(uint8_t a, uint8_t b) const {
    return static_cast<uint8_t>(a ^ b);
}

uint16_t GaloisField::rawMultiply(uint8_t a, uint8_t b) {
    uint16_t result = 0;
    for (int i = 0; i < 8; ++i) {
        uint16_t bitMask = static_cast<uint16_t>(0) - static_cast<uint16_t>((b >> i) & 1);
        result = static_cast<uint16_t>(result ^ (bitMask & (static_cast<uint16_t>(a) << i)));
    }
    return result;
}

uint8_t GaloisField::reduce(uint16_t value) const {
    for (int i = 14; i >= 8; --i) {
        uint16_t bitMask = static_cast<uint16_t>(0) - static_cast<uint16_t>((value >> i) & 1);
        value = static_cast<uint16_t>(value ^ (bitMask & (static_cast<uint16_t>(modulus_) << (i - 8))));
    }
    return static_cast<uint8_t>(value);
}

uint8_t GaloisField::multiply(uint8_t a, uint8_t b) const {
    return reduce(rawMultiply(a, b));
}

uint8_t GaloisField::multiplyKaratsuba(uint8_t a, uint8_t b) const {
    uint8_t a1 = static_cast<uint8_t>(a >> 4);
    uint8_t a0 = static_cast<uint8_t>(a & 0x0F);
    uint8_t b1 = static_cast<uint8_t>(b >> 4);
    uint8_t b0 = static_cast<uint8_t>(b & 0x0F);

    uint16_t p0 = rawMultiply(a0, b0);
    uint16_t p2 = rawMultiply(a1, b1);
    uint16_t p1 = rawMultiply(static_cast<uint8_t>(a0 ^ a1), static_cast<uint8_t>(b0 ^ b1));

    uint16_t mid = static_cast<uint16_t>(p0 ^ p1 ^ p2);
    uint16_t raw = static_cast<uint16_t>((p2 << 8) ^ (mid << 4) ^ p0);

    return reduce(raw);
}

uint8_t GaloisField::power(uint8_t a, unsigned int exponent) const {
    uint8_t result = 1;
    uint8_t base = a;
    unsigned int e = exponent;
    while (e > 0) {
        if (e & 1u) {
            result = multiplyKaratsuba(result, base);
        }
        base = multiplyKaratsuba(base, base);
        e >>= 1;
    }
    return result;
}

uint8_t GaloisField::inverse(uint8_t a) const {
    uint8_t a2 = multiplyKaratsuba(a, a);
    uint8_t a4 = multiplyKaratsuba(a2, a2);
    uint8_t a8 = multiplyKaratsuba(a4, a4);
    uint8_t a16 = multiplyKaratsuba(a8, a8);
    uint8_t a32 = multiplyKaratsuba(a16, a16);
    uint8_t a64 = multiplyKaratsuba(a32, a32);
    uint8_t a128 = multiplyKaratsuba(a64, a64);

    uint8_t result = multiplyKaratsuba(a128, a64);
    result = multiplyKaratsuba(result, a32);
    result = multiplyKaratsuba(result, a16);
    result = multiplyKaratsuba(result, a8);
    result = multiplyKaratsuba(result, a4);
    result = multiplyKaratsuba(result, a2);
    return result;
}

uint8_t GaloisField::affineTransform(uint8_t value) {
    uint8_t result = 0;
    const uint8_t c = 0x63;
    for (int i = 0; i < 8; ++i) {
        uint8_t bit = 0;
        bit = static_cast<uint8_t>(bit ^ ((value >> i) & 1));
        bit = static_cast<uint8_t>(bit ^ ((value >> ((i + 4) % 8)) & 1));
        bit = static_cast<uint8_t>(bit ^ ((value >> ((i + 5) % 8)) & 1));
        bit = static_cast<uint8_t>(bit ^ ((value >> ((i + 6) % 8)) & 1));
        bit = static_cast<uint8_t>(bit ^ ((value >> ((i + 7) % 8)) & 1));
        bit = static_cast<uint8_t>(bit ^ ((c >> i) & 1));
        result = static_cast<uint8_t>(result | (bit << i));
    }
    return result;
}

void GaloisField::generateSBox(uint8_t sbox[256], uint8_t invSbox[256]) const {
    for (int b = 0; b < 256; ++b) {
        uint8_t inv = inverse(static_cast<uint8_t>(b));
        sbox[b] = affineTransform(inv);
    }
    for (int b = 0; b < 256; ++b) {
        invSbox[sbox[b]] = static_cast<uint8_t>(b);
    }
}
