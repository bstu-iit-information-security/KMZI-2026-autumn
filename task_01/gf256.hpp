#pragma once
#include <array>
#include <cstdint>

class GaloisField {
public:
    static uint8_t add(uint8_t a, uint8_t b) {
        return static_cast<uint8_t>(a ^ b);
    }

    static uint8_t xtime(uint8_t b, uint16_t p_x) {
        uint8_t mask = static_cast<uint8_t>(0u - ((b >> 7) & 1u));
        uint8_t reduce = static_cast<uint8_t>(p_x & 0xFFu);
        return static_cast<uint8_t>((b << 1) ^ (mask & reduce));
    }

    static uint8_t multiply(uint8_t a, uint8_t b, uint16_t p_x) {
        uint8_t result = 0;
        for (int i = 0; i < 8; ++i) {
            uint8_t mask = static_cast<uint8_t>(0u - (b & 1u));
            result = static_cast<uint8_t>(result ^ (a & mask));
            a = xtime(a, p_x);
            b = static_cast<uint8_t>(b >> 1);
        }
        return result;
    }

    static uint8_t inverse(uint8_t a, uint16_t p_x) {
        uint8_t square = multiply(a, a, p_x);
        uint8_t result = square;
        for (int i = 0; i < 6; ++i) {
            square = multiply(square, square, p_x);
            result = multiply(result, square, p_x);
        }
        return result;
    }

    static uint8_t rotl8(uint8_t x, int r) {
        return static_cast<uint8_t>((x << r) | (x >> (8 - r)));
    }

    static uint8_t affine(uint8_t b) {
        return static_cast<uint8_t>(b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63u);
    }

    static std::array<uint8_t, 256> buildSBox(uint16_t p_x) {
        std::array<uint8_t, 256> table{};
        for (int i = 0; i < 256; ++i) {
            table[i] = affine(inverse(static_cast<uint8_t>(i), p_x));
        }
        return table;
    }
};
