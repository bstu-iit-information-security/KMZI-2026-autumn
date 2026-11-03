#include "aes128.hpp"

#include <cstring>

Aes128::Aes128(const uint8_t key[kBlock], uint16_t poly) : gf_(poly) {
    gf_.fill_sbox(sbox_);
    for (int i = 0; i < 256; ++i) {
        inv_sbox_[sbox_[i]] = static_cast<uint8_t>(i);
    }
    expand_key(key);
}

void Aes128::expand_key(const uint8_t key[kBlock]) {
    std::memcpy(round_keys_, key, kBlock);

    uint8_t rcon = 0x01;
    for (int word = 4; word < 44; ++word) {
        uint8_t temp[4] = {
            round_keys_[4 * word - 4],
            round_keys_[4 * word - 3],
            round_keys_[4 * word - 2],
            round_keys_[4 * word - 1],
        };
        if (word % 4 == 0) {
            const uint8_t first = temp[0];
            temp[0] = static_cast<uint8_t>(sbox_[temp[1]] ^ rcon);
            temp[1] = sbox_[temp[2]];
            temp[2] = sbox_[temp[3]];
            temp[3] = sbox_[first];
            rcon = gf_.xtime(rcon);
        }
        for (int byte = 0; byte < 4; ++byte) {
            round_keys_[4 * word + byte] =
                static_cast<uint8_t>(round_keys_[4 * (word - 4) + byte] ^ temp[byte]);
        }
    }
}

void Aes128::sub_bytes(uint8_t state[kBlock], const uint8_t box[256]) const {
    for (int i = 0; i < kBlock; ++i) {
        state[i] = box[state[i]];
    }
}

void Aes128::shift_rows(uint8_t state[kBlock]) {
    const uint8_t saved[kBlock] = {
        state[0], state[1], state[2], state[3],
        state[4], state[5], state[6], state[7],
        state[8], state[9], state[10], state[11],
        state[12], state[13], state[14], state[15],
    };
    for (int row = 1; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            state[row + 4 * col] = saved[row + 4 * ((col + row) & 3)];
        }
    }
}

void Aes128::inv_shift_rows(uint8_t state[kBlock]) {
    const uint8_t saved[kBlock] = {
        state[0], state[1], state[2], state[3],
        state[4], state[5], state[6], state[7],
        state[8], state[9], state[10], state[11],
        state[12], state[13], state[14], state[15],
    };
    for (int row = 1; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            state[row + 4 * col] = saved[row + 4 * ((col - row + 4) & 3)];
        }
    }
}

void Aes128::mix_columns(uint8_t state[kBlock]) const {
    for (int col = 0; col < 4; ++col) {
        const uint8_t s0 = state[4 * col];
        const uint8_t s1 = state[4 * col + 1];
        const uint8_t s2 = state[4 * col + 2];
        const uint8_t s3 = state[4 * col + 3];
        state[4 * col] = static_cast<uint8_t>(gf_.multiply(s0, 0x02) ^ gf_.multiply(s1, 0x03) ^ s2 ^ s3);
        state[4 * col + 1] = static_cast<uint8_t>(s0 ^ gf_.multiply(s1, 0x02) ^ gf_.multiply(s2, 0x03) ^ s3);
        state[4 * col + 2] = static_cast<uint8_t>(s0 ^ s1 ^ gf_.multiply(s2, 0x02) ^ gf_.multiply(s3, 0x03));
        state[4 * col + 3] = static_cast<uint8_t>(gf_.multiply(s0, 0x03) ^ s1 ^ s2 ^ gf_.multiply(s3, 0x02));
    }
}

void Aes128::inv_mix_columns(uint8_t state[kBlock]) const {
    for (int col = 0; col < 4; ++col) {
        const uint8_t s0 = state[4 * col];
        const uint8_t s1 = state[4 * col + 1];
        const uint8_t s2 = state[4 * col + 2];
        const uint8_t s3 = state[4 * col + 3];
        state[4 * col] = static_cast<uint8_t>(
            gf_.multiply(s0, 0x0E) ^ gf_.multiply(s1, 0x0B) ^ gf_.multiply(s2, 0x0D) ^ gf_.multiply(s3, 0x09));
        state[4 * col + 1] = static_cast<uint8_t>(
            gf_.multiply(s0, 0x09) ^ gf_.multiply(s1, 0x0E) ^ gf_.multiply(s2, 0x0B) ^ gf_.multiply(s3, 0x0D));
        state[4 * col + 2] = static_cast<uint8_t>(
            gf_.multiply(s0, 0x0D) ^ gf_.multiply(s1, 0x09) ^ gf_.multiply(s2, 0x0E) ^ gf_.multiply(s3, 0x0B));
        state[4 * col + 3] = static_cast<uint8_t>(
            gf_.multiply(s0, 0x0B) ^ gf_.multiply(s1, 0x0D) ^ gf_.multiply(s2, 0x09) ^ gf_.multiply(s3, 0x0E));
    }
}

void Aes128::add_round_key(uint8_t state[kBlock], int round) const {
    const uint8_t* key = round_keys_ + round * kBlock;
    for (int i = 0; i < kBlock; ++i) {
        state[i] ^= key[i];
    }
}

void Aes128::encrypt_block(const uint8_t in[kBlock], uint8_t out[kBlock]) const {
    uint8_t state[kBlock];
    std::memcpy(state, in, kBlock);
    add_round_key(state, 0);
    for (int round = 1; round < 10; ++round) {
        sub_bytes(state, sbox_);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round);
    }
    sub_bytes(state, sbox_);
    shift_rows(state);
    add_round_key(state, 10);
    std::memcpy(out, state, kBlock);
}

void Aes128::decrypt_block(const uint8_t in[kBlock], uint8_t out[kBlock]) const {
    uint8_t state[kBlock];
    std::memcpy(state, in, kBlock);
    add_round_key(state, 10);
    for (int round = 9; round > 0; --round) {
        inv_shift_rows(state);
        sub_bytes(state, inv_sbox_);
        add_round_key(state, round);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    sub_bytes(state, inv_sbox_);
    add_round_key(state, 0);
    std::memcpy(out, state, kBlock);
}
