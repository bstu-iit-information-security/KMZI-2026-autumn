#pragma once

#include "gf8.hpp"

#include <cstdint>

class Aes128 {
public:
    static constexpr int kBlock = 16;

    Aes128(const uint8_t key[kBlock], uint16_t poly = Gf8::kPoly);

    void encrypt_block(const uint8_t in[kBlock], uint8_t out[kBlock]) const;
    void decrypt_block(const uint8_t in[kBlock], uint8_t out[kBlock]) const;

private:
    Gf8 gf_;
    uint8_t sbox_[256]{};
    uint8_t inv_sbox_[256]{};
    uint8_t round_keys_[176]{};

    void expand_key(const uint8_t key[kBlock]);
    void sub_bytes(uint8_t state[kBlock], const uint8_t box[256]) const;
    void mix_columns(uint8_t state[kBlock]) const;
    void inv_mix_columns(uint8_t state[kBlock]) const;
    void add_round_key(uint8_t state[kBlock], int round) const;

    static void shift_rows(uint8_t state[kBlock]);
    static void inv_shift_rows(uint8_t state[kBlock]);
};
