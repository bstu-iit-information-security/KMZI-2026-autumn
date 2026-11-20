#pragma once

#include <cstdint>

class Gf8 {
public:
    static constexpr uint16_t kPoly = 0x14D;

    explicit Gf8(uint16_t poly = kPoly);

    uint16_t polynomial() const { return poly_; }

    static uint8_t add(uint8_t a, uint8_t b) { return static_cast<uint8_t>(a ^ b); }

    uint8_t multiply(uint8_t a, uint8_t b) const;
    uint8_t inverse(uint8_t a) const;
    uint8_t xtime(uint8_t a) const;
    void fill_sbox(uint8_t sbox[256]) const;

private:
    uint16_t poly_;

    uint8_t reduce(uint16_t value) const;
    static uint8_t mul_nibble(uint8_t a, uint8_t b);
    static uint8_t affine(uint8_t value);
};
