#pragma once

#include <array>
#include <cstdint>

using SBox = std::array<uint8_t, 256>;

class GaloisField {
public:
    explicit GaloisField(uint16_t p_x);

    uint16_t modulus() const;

    static uint8_t add(uint8_t a, uint8_t b);
    static uint8_t multiply(uint8_t a, uint8_t b, uint16_t p_x);
    static uint8_t inverse(uint8_t a, uint16_t p_x);
    static bool isIrreducible(uint16_t p_x);

    SBox generateSBox() const;

private:
    uint16_t p_x_;
};
