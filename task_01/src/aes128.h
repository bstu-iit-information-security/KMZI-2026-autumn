#ifndef AES128_H
#define AES128_H

#include <cstdint>
#include "galois.h"

class AES128 {
public:
    AES128(const GaloisField& field, const uint8_t key[16]);

    void encryptBlock(const uint8_t input[16], uint8_t output[16]) const;

private:
    const GaloisField& field_;
    uint8_t sbox_[256];
    uint8_t invSbox_[256];
    uint8_t roundKeys_[11][16];

    void keyExpansion(const uint8_t key[16]);
    void subBytes(uint8_t state[16]) const;
    void shiftRows(uint8_t state[16]) const;
    void mixColumns(uint8_t state[16]) const;
    void addRoundKey(uint8_t state[16], int round) const;
    uint8_t rcon(unsigned int index) const;
};

#endif
