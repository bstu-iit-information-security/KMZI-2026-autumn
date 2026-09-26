#include <array>
#include <cstdint>

namespace gf256 {

uint8_t add(uint8_t a, uint8_t b) {
    return static_cast<uint8_t>(a ^ b);
}

uint8_t multiply(uint8_t a, uint8_t b, uint16_t polynomial) {
    uint8_t result = 0;
    const uint8_t reduction = static_cast<uint8_t>(polynomial & 0xFFu);

    for (int i = 0; i < 8; ++i) {
        const uint8_t bMask = static_cast<uint8_t>(0u - (b & 1u));
        result ^= static_cast<uint8_t>(a & bMask);

        const uint8_t highBit = static_cast<uint8_t>(a >> 7);
        const uint8_t reductionMask = static_cast<uint8_t>(0u - highBit);
        a = static_cast<uint8_t>((a << 1) ^ (reduction & reductionMask));
        b >>= 1;
    }

    return result;
}

uint8_t inverse(uint8_t a, uint16_t polynomial) {
    uint8_t result = 1;
    uint8_t base = a;
    uint8_t exponent = 254;

    for (int i = 0; i < 8; ++i) {
        const uint8_t product = multiply(result, base, polynomial);
        const uint8_t bitMask = static_cast<uint8_t>(0u - (exponent & 1u));
        result = static_cast<uint8_t>((result & static_cast<uint8_t>(~bitMask)) |
                                      (product & bitMask));

        base = multiply(base, base, polynomial);
        exponent >>= 1;
    }

    return result;
}

std::array<uint8_t, 256> generateSBox(uint16_t polynomial) {
    std::array<uint8_t, 256> sBox{};

    for (int i = 0; i < 256; ++i) {
        const uint8_t x = inverse(static_cast<uint8_t>(i), polynomial);

        const uint8_t r1 = static_cast<uint8_t>((x << 1) | (x >> 7));
        const uint8_t r2 = static_cast<uint8_t>((x << 2) | (x >> 6));
        const uint8_t r3 = static_cast<uint8_t>((x << 3) | (x >> 5));
        const uint8_t r4 = static_cast<uint8_t>((x << 4) | (x >> 4));

        sBox[i] = static_cast<uint8_t>(x ^ r1 ^ r2 ^ r3 ^ r4 ^ 0x63u);
    }

    return sBox;
}

}
