#pragma once

#include "common.hpp"
#include "number_theory.hpp"
#include "rsa_core.hpp"

#include <cstddef>
#include <cstdint>

namespace rsa {

struct OaepResult {
    bool ok;
    std::size_t len;
    uint8_t msg[kModulusBytes];
};

class OaepEngine {
public:
    OaepEngine() = default;

    bool encode(const uint8_t* msg, std::size_t msg_len, uint8_t em[kModulusBytes]);
    OaepResult decode(const uint8_t em[kModulusBytes]);

    struct Delim {
        uint32_t one_pos;
        uint32_t found;
        uint32_t ps_ok;
    };
    static Delim find_delimiter(const uint8_t* db, std::size_t db_len);

private:
    void hash(const uint8_t* data, std::size_t len, uint8_t out[kHashLen]);
    void mgf1(const uint8_t* seed, std::size_t seed_len, uint8_t* mask, std::size_t mask_len);

    uint8_t lhash_[kHashLen];
    uint8_t seed_[kHashLen];
    uint8_t db_[kModulusBytes];
    uint8_t masked_db_[kModulusBytes];
    uint8_t db_mask_[kModulusBytes];
    uint8_t seed_mask_[kHashLen];
    uint8_t mgf_block_[kModulusBytes + 4];
    uint8_t mgf_hash_[kHashLen];
};

bool rsa_oaep_encrypt(const uint8_t* msg, std::size_t msg_len, const KeyPair& kp,
                      uint8_t ct[kModulusBytes]);
OaepResult rsa_oaep_decrypt(const uint8_t ct[kModulusBytes], const KeyPair& kp);

}  