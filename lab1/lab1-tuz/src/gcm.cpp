#include "gcm.hpp"

#include <cstring>

AesGcm::AesGcm(const uint8_t key[Aes128::kBlock], uint16_t poly) : aes_(key, poly) {
    const uint8_t zero[kBlock] = {};
    aes_.encrypt_block(zero, h_);
}

bool AesGcm::tags_equal(const uint8_t a[kTag], const uint8_t b[kTag]) {
    uint8_t acc = 0;
    for (int i = 0; i < kTag; ++i) {
        acc |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return acc == 0;
}

void AesGcm::inc32(uint8_t block[kBlock]) {
    const uint32_t next = ((static_cast<uint32_t>(block[12]) << 24) |
                           (static_cast<uint32_t>(block[13]) << 16) |
                           (static_cast<uint32_t>(block[14]) << 8) |
                           static_cast<uint32_t>(block[15])) +
                          1u;
    block[12] = static_cast<uint8_t>(next >> 24);
    block[13] = static_cast<uint8_t>(next >> 16);
    block[14] = static_cast<uint8_t>(next >> 8);
    block[15] = static_cast<uint8_t>(next);
}

void AesGcm::gf128_mul(uint8_t z[kBlock], const uint8_t x[kBlock], const uint8_t y[kBlock]) {
    uint8_t v[kBlock];
    std::memcpy(v, y, kBlock);
    std::memset(z, 0, kBlock);

    for (int bit_index = 0; bit_index < 128; ++bit_index) {
        const uint8_t bit = static_cast<uint8_t>((x[bit_index >> 3] >> (7 - (bit_index & 7))) & 1u);
        const uint8_t mask = static_cast<uint8_t>(0u - bit);
        for (int i = 0; i < kBlock; ++i) {
            z[i] ^= static_cast<uint8_t>(v[i] & mask);
        }

        const uint8_t lsb = static_cast<uint8_t>(v[15] & 1u);
        for (int i = 15; i > 0; --i) {
            v[i] = static_cast<uint8_t>((v[i] >> 1) | (v[i - 1] << 7));
        }
        v[0] = static_cast<uint8_t>(v[0] >> 1);
        v[0] ^= static_cast<uint8_t>(0xE1 & static_cast<uint8_t>(0u - lsb));
    }
}

void AesGcm::absorb(uint8_t y[kBlock], const uint8_t* data, std::size_t len) const {
    std::size_t offset = 0;
    while (offset < len) {
        uint8_t block[kBlock] = {};
        const std::size_t n = (len - offset < kBlock) ? (len - offset) : kBlock;
        std::memcpy(block, data + offset, n);
        for (int i = 0; i < kBlock; ++i) {
            y[i] ^= block[i];
        }
        uint8_t product[kBlock];
        gf128_mul(product, y, h_);
        std::memcpy(y, product, kBlock);
        offset += n;
    }
}

void AesGcm::ghash(const uint8_t* aad, std::size_t aad_len,
                   const uint8_t* data, std::size_t data_len,
                   uint8_t out[kBlock]) const {
    uint8_t y[kBlock] = {};
    absorb(y, aad, aad_len);
    absorb(y, data, data_len);

    uint8_t lengths[kBlock] = {};
    const uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8u;
    const uint64_t data_bits = static_cast<uint64_t>(data_len) * 8u;
    for (int i = 0; i < 8; ++i) {
        lengths[i] = static_cast<uint8_t>(aad_bits >> (56 - 8 * i));
        lengths[8 + i] = static_cast<uint8_t>(data_bits >> (56 - 8 * i));
    }
    for (int i = 0; i < kBlock; ++i) {
        y[i] ^= lengths[i];
    }
    gf128_mul(out, y, h_);
}

void AesGcm::ctr(const uint8_t iv[kIv], const uint8_t* in, std::size_t len, uint8_t* out) const {
    uint8_t counter[kBlock] = {};
    std::memcpy(counter, iv, kIv);
    counter[15] = 1;
    inc32(counter);

    std::size_t offset = 0;
    while (offset < len) {
        uint8_t keystream[kBlock];
        aes_.encrypt_block(counter, keystream);
        const std::size_t n = (len - offset < kBlock) ? (len - offset) : kBlock;
        for (std::size_t i = 0; i < n; ++i) {
            out[offset + i] = static_cast<uint8_t>(in[offset + i] ^ keystream[i]);
        }
        inc32(counter);
        offset += n;
    }
}

void AesGcm::encrypt(const uint8_t iv[kIv],
                     const uint8_t* aad, std::size_t aad_len,
                     const uint8_t* plain, std::size_t plain_len,
                     uint8_t* cipher,
                     uint8_t tag[kTag]) const {
    if (plain_len > 0) {
        ctr(iv, plain, plain_len, cipher);
    }

    uint8_t hash[kBlock];
    ghash(aad, aad_len, cipher, plain_len, hash);

    uint8_t j0[kBlock] = {};
    std::memcpy(j0, iv, kIv);
    j0[15] = 1;
    uint8_t mask[kBlock];
    aes_.encrypt_block(j0, mask);
    for (int i = 0; i < kTag; ++i) {
        tag[i] = static_cast<uint8_t>(hash[i] ^ mask[i]);
    }
}

bool AesGcm::decrypt(const uint8_t iv[kIv],
                     const uint8_t* aad, std::size_t aad_len,
                     const uint8_t* cipher, std::size_t cipher_len,
                     const uint8_t tag[kTag],
                     uint8_t* plain) const {
    uint8_t hash[kBlock];
    ghash(aad, aad_len, cipher, cipher_len, hash);

    uint8_t j0[kBlock] = {};
    std::memcpy(j0, iv, kIv);
    j0[15] = 1;
    uint8_t mask[kBlock];
    aes_.encrypt_block(j0, mask);

    uint8_t expected[kTag];
    for (int i = 0; i < kTag; ++i) {
        expected[i] = static_cast<uint8_t>(hash[i] ^ mask[i]);
    }
    if (!tags_equal(expected, tag)) {
        for (std::size_t i = 0; i < cipher_len; ++i) {
            plain[i] = 0;
        }
        return false;
    }
    if (cipher_len > 0) {
        ctr(iv, cipher, cipher_len, plain);
    }
    return true;
}
