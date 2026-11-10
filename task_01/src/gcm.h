#ifndef GCM_H
#define GCM_H

#include <cstdint>
#include <cstddef>
#include "aes128.h"

class GCM {
public:
    explicit GCM(const AES128& cipher);

    void encrypt(const uint8_t iv[12],
                 const uint8_t* aad, size_t aadLen,
                 const uint8_t* plaintext, size_t ptLen,
                 uint8_t* ciphertext,
                 uint8_t tag[16]) const;

    bool decrypt(const uint8_t iv[12],
                 const uint8_t* aad, size_t aadLen,
                 const uint8_t* ciphertext, size_t ctLen,
                 const uint8_t tag[16],
                 uint8_t* plaintext) const;

private:
    const AES128& cipher_;
    uint8_t h_[16];

    void gf128Multiply(const uint8_t x[16], const uint8_t y[16], uint8_t result[16]) const;
    void ghash(const uint8_t* aad, size_t aadLen, const uint8_t* data, size_t dataLen, uint8_t result[16]) const;
    void computeJ0(const uint8_t iv[12], uint8_t j0[16]) const;
    void incrementCounter(uint8_t block[16]) const;
    void ctrProcess(const uint8_t j0[16], const uint8_t* input, size_t len, uint8_t* output) const;
    static bool constantTimeEqual(const uint8_t a[16], const uint8_t b[16]);
};

#endif
