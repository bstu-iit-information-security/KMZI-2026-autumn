#pragma once

#include "aes128.hpp"

#include <cstddef>
#include <cstdint>

class AesGcm {
public:
    static constexpr int kBlock = 16;
    static constexpr int kTag = 16;
    static constexpr int kIv = 12;

    AesGcm(const uint8_t key[Aes128::kBlock], uint16_t poly = Gf8::kPoly);

    void encrypt(const uint8_t iv[kIv],
                 const uint8_t* aad, std::size_t aad_len,
                 const uint8_t* plain, std::size_t plain_len,
                 uint8_t* cipher,
                 uint8_t tag[kTag]) const;

    bool decrypt(const uint8_t iv[kIv],
                 const uint8_t* aad, std::size_t aad_len,
                 const uint8_t* cipher, std::size_t cipher_len,
                 const uint8_t tag[kTag],
                 uint8_t* plain) const;

    static bool tags_equal(const uint8_t a[kTag], const uint8_t b[kTag]);

private:
    Aes128 aes_;
    uint8_t h_[kBlock]{};

    void ctr(const uint8_t iv[kIv], const uint8_t* in, std::size_t len, uint8_t* out) const;
    void ghash(const uint8_t* aad, std::size_t aad_len,
               const uint8_t* data, std::size_t data_len,
               uint8_t out[kBlock]) const;
    void absorb(uint8_t y[kBlock], const uint8_t* data, std::size_t len) const;

    static void gf128_mul(uint8_t z[kBlock], const uint8_t x[kBlock], const uint8_t y[kBlock]);
    static void inc32(uint8_t block[kBlock]);
};
