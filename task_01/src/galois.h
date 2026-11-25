#ifndef GALOIS_H
#define GALOIS_H

#include <cstdint>

class GaloisField {
public:
    explicit GaloisField(uint16_t modulus);

    uint8_t add(uint8_t a, uint8_t b) const;
    uint8_t multiply(uint8_t a, uint8_t b) const;
    uint8_t multiplyKaratsuba(uint8_t a, uint8_t b) const;
    uint8_t power(uint8_t a, unsigned int exponent) const;
    uint8_t inverse(uint8_t a) const;
    void generateSBox(uint8_t sbox[256], uint8_t invSbox[256]) const;
    uint16_t modulus() const;

private:
    uint16_t modulus_;

    static uint16_t rawMultiply(uint8_t a, uint8_t b);
    uint8_t reduce(uint16_t value) const;
    static uint8_t affineTransform(uint8_t value);
};

#endif
