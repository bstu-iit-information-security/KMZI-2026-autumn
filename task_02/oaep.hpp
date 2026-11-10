#pragma once
#include "rsa_core.hpp"
#include "sha256.hpp"
#include <cstddef>
#include <cstdint>

constexpr size_t OAEP_K = 256;
constexpr size_t OAEP_HLEN = SHA256_DIGEST_SIZE;
constexpr size_t OAEP_DBLEN = OAEP_K - OAEP_HLEN - 1;
constexpr size_t OAEP_MAX_MSG = OAEP_K - 2 * OAEP_HLEN - 2;

struct OaepResult {
    uint32_t ok;
    uint32_t len;
    uint8_t msg[OAEP_MAX_MSG];
};

void oaep_encode(const uint8_t db[OAEP_DBLEN], const uint8_t seed[OAEP_HLEN], uint8_t em[OAEP_K]);
bool oaep_pad(const uint8_t* msg, size_t mlen, const uint8_t* label, size_t llen, uint8_t em[OAEP_K]);
void oaep_unpad(const uint8_t em[OAEP_K], const uint8_t* label, size_t llen, OaepResult& out);

bool oaep_encrypt(const uint8_t* msg, size_t mlen, const uint8_t* label, size_t llen,
                  const PublicKey& key, uint8_t ct[OAEP_K]);
bool oaep_decrypt(const uint8_t ct[OAEP_K], const uint8_t* label, size_t llen,
                  const PrivateKey& key, OaepResult& out);
