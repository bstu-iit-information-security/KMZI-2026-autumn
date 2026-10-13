#pragma once
#include <cstdint>
#include "gf256.h"

namespace lab1 {

    class AES128 {
    public:
        AES128(const uint8_t key[16], const GaloisField& gf);

        void encryptBlock(const uint8_t in[16], uint8_t out[16]) const;
        void decryptBlock(const uint8_t in[16], uint8_t out[16]) const;

    private:
        const GaloisField& gf_;
        uint8_t roundKeys_[11][16];
        uint8_t invSbox_[256];
        uint8_t invMixMatrix_[4][4];   // обратная матрица MixColumns для данного поля

        void keyExpansion(const uint8_t key[16]);
        void buildInvSbox();
        void computeInvMixMatrix();

        void subBytes(uint8_t s[16]) const;
        void invSubBytes(uint8_t s[16]) const;
        void shiftRows(uint8_t s[16]) const;
        void invShiftRows(uint8_t s[16]) const;
        void mixColumns(uint8_t s[16]) const;      // constant-time
        void invMixColumns(uint8_t s[16]) const;   // constant-time
        void addRoundKey(uint8_t s[16], const uint8_t rk[16]) const;
    };

} // namespace lab1