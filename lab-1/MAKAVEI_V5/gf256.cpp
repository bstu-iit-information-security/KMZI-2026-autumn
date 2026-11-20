#include "gf256.h"

namespace lab1 {

    GaloisField::GaloisField(uint16_t poly)
        : poly_(poly),
        poly_byte_(static_cast<uint8_t>(poly & 0xFF)) {
        buildSbox();
    }

    // --- Умножение (shift-and-XOR) ---
    // a·b в GF(2^8) mod p(x).
    // Реализовано constant-time: маска -(y&1) заменяет if (y&1),
    // маска -(hi) заменяет ветвление при редукции.
    uint8_t GaloisField::multiply(uint8_t a, uint8_t b) const {
        uint8_t result = 0;
        uint8_t x = a;
        uint8_t y = b;

        for (int i = 0; i < 8; ++i) {
            uint8_t mask = static_cast<uint8_t>(-(y & 1));
            result ^= static_cast<uint8_t>(x & mask);

            uint8_t hi = static_cast<uint8_t>(x >> 7);
            x = static_cast<uint8_t>(x << 1);
            uint8_t rmask = static_cast<uint8_t>(-hi);
            x ^= static_cast<uint8_t>(poly_byte_ & rmask);

            y = static_cast<uint8_t>(y >> 1);
        }
        return result;
    }

    // --- Возведение в степень ---
    uint8_t GaloisField::power(uint8_t a, uint16_t n) const {
        uint8_t result = 1;
        uint8_t base = a;
        for (int i = 0; i < 16; ++i) {
            uint8_t bit = static_cast<uint8_t>((n >> i) & 1);
            uint8_t mask = static_cast<uint8_t>(-bit);
            // result *= (bit ? base : 1)
            uint8_t factor = static_cast<uint8_t>((base & mask) | (1u & ~mask));
            result = multiply(result, factor);
            base = multiply(base, base);
        }
        return result;
    }

    // --- Обратный элемент (a^254) ---
    // a^254 = a^128 · a^64 · a^32 · a^16 · a^8 · a^4 · a^2
    // Для a = 0 возвращаем 0 через маску, без ветвления.
    uint8_t GaloisField::inverse(uint8_t a) const {
        uint8_t a2 = multiply(a, a);
        uint8_t a4 = multiply(a2, a2);
        uint8_t a8 = multiply(a4, a4);
        uint8_t a16 = multiply(a8, a8);
        uint8_t a32 = multiply(a16, a16);
        uint8_t a64 = multiply(a32, a32);
        uint8_t a128 = multiply(a64, a64);

        uint8_t inv = a2;
        inv = multiply(inv, a4);
        inv = multiply(inv, a8);
        inv = multiply(inv, a16);
        inv = multiply(inv, a32);
        inv = multiply(inv, a64);
        inv = multiply(inv, a128);

        // mask = 0xFF, если a != 0; 0x00, если a == 0.
        uint8_t t = static_cast<uint8_t>(a | static_cast<uint8_t>(-a));
        uint8_t mask = static_cast<uint8_t>(-(t >> 7));
        return static_cast<uint8_t>(inv & mask);
    }

    // --- Аффинное преобразование S-box ---
    // s(x) = x ⊕ ROTL(x,1) ⊕ ROTL(x,2) ⊕ ROTL(x,3) ⊕ ROTL(x,4) ⊕ 0x63
    uint8_t GaloisField::affineTransform(uint8_t x) {
        auto rotl = [](uint8_t v, int n) -> uint8_t {
            return static_cast<uint8_t>((v << n) | (v >> (8 - n)));
            };
        uint8_t y = x;
        y ^= rotl(x, 1);
        y ^= rotl(x, 2);
        y ^= rotl(x, 3);
        y ^= rotl(x, 4);
        y ^= 0x63;
        return y;
    }

    void GaloisField::buildSbox() {
        for (int i = 0; i < 256; ++i) {
            uint8_t inv = inverse(static_cast<uint8_t>(i));
            sbox_[i] = affineTransform(inv);
        }
    }

} // namespace lab1