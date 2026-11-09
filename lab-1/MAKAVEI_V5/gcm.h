#pragma once
#include <cstdint>
#include <cstddef>
#include "gf256.h"
#include "aes128.h"

namespace lab1 {

    // ”множение в GF(2^128) по f(x)=x^128+x^7+x^2+x+1 (constant-time).
    void gf128_mul(const uint8_t X[16], const uint8_t Y[16], uint8_t Z[16]);

    // GHASH_H(AAD, C)
    void ghash(const uint8_t H[16],
        const uint8_t* aad, size_t aad_len,
        const uint8_t* ciph, size_t ciph_len,
        uint8_t out[16]);

    // —равнение тегов за константное врем€ (без раннего выхода)
    bool constantTimeCompare(const uint8_t* a, const uint8_t* b, size_t len);

    class GCM {
    public:
        GCM(const uint8_t key[16], uint16_t gf_poly);

        // IV = 96 бит (стандартный вариант GCM)
        void encrypt(const uint8_t iv[12],
            const uint8_t* aad, size_t aad_len,
            const uint8_t* pt, size_t pt_len,
            uint8_t* ct, uint8_t tag[16]);

        bool decrypt(const uint8_t iv[12],
            const uint8_t* aad, size_t aad_len,
            const uint8_t* ct, size_t ct_len,
            uint8_t* pt, const uint8_t tag[16]);

        const GaloisField& field() const { return gf_; }

    private:
        GaloisField gf_;
        AES128     aes_;
    };

} // namespace lab1