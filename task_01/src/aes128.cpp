#include "aes128.h"

AES128::AES128(const GaloisField& field, const uint8_t key[16]) : field_(field) {
    field_.generateSBox(sbox_, invSbox_);
    keyExpansion(key);
}

uint8_t AES128::rcon(unsigned int index) const {
    return field_.power(0x02, index - 1);
}

void AES128::keyExpansion(const uint8_t key[16]) {
    uint8_t w[44][4];

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            w[i][j] = key[i * 4 + j];
        }
    }

    for (int i = 4; i < 44; ++i) {
        uint8_t temp[4] = { w[i - 1][0], w[i - 1][1], w[i - 1][2], w[i - 1][3] };

        if (i % 4 == 0) {
            uint8_t rotated[4] = { temp[1], temp[2], temp[3], temp[0] };
            uint8_t subbed[4];
            for (int k = 0; k < 4; ++k) {
                subbed[k] = sbox_[rotated[k]];
            }
            subbed[0] = static_cast<uint8_t>(subbed[0] ^ rcon(i / 4));
            for (int k = 0; k < 4; ++k) {
                temp[k] = subbed[k];
            }
        }

        for (int k = 0; k < 4; ++k) {
            w[i][k] = static_cast<uint8_t>(w[i - 4][k] ^ temp[k]);
        }
    }

    for (int r = 0; r < 11; ++r) {
        for (int col = 0; col < 4; ++col) {
            for (int row = 0; row < 4; ++row) {
                roundKeys_[r][row + 4 * col] = w[r * 4 + col][row];
            }
        }
    }
}

void AES128::subBytes(uint8_t state[16]) const {
    for (int i = 0; i < 16; ++i) {
        state[i] = sbox_[state[i]];
    }
}

void AES128::shiftRows(uint8_t state[16]) const {
    uint8_t temp[16];
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            temp[row + 4 * col] = state[row + 4 * ((col + row) % 4)];
        }
    }
    for (int i = 0; i < 16; ++i) {
        state[i] = temp[i];
    }
}

void AES128::mixColumns(uint8_t state[16]) const {
    for (int col = 0; col < 4; ++col) {
        uint8_t s0 = state[4 * col + 0];
        uint8_t s1 = state[4 * col + 1];
        uint8_t s2 = state[4 * col + 2];
        uint8_t s3 = state[4 * col + 3];

        uint8_t r0 = static_cast<uint8_t>(field_.multiplyKaratsuba(0x02, s0) ^ field_.multiplyKaratsuba(0x03, s1) ^ s2 ^ s3);
        uint8_t r1 = static_cast<uint8_t>(s0 ^ field_.multiplyKaratsuba(0x02, s1) ^ field_.multiplyKaratsuba(0x03, s2) ^ s3);
        uint8_t r2 = static_cast<uint8_t>(s0 ^ s1 ^ field_.multiplyKaratsuba(0x02, s2) ^ field_.multiplyKaratsuba(0x03, s3));
        uint8_t r3 = static_cast<uint8_t>(field_.multiplyKaratsuba(0x03, s0) ^ s1 ^ s2 ^ field_.multiplyKaratsuba(0x02, s3));

        state[4 * col + 0] = r0;
        state[4 * col + 1] = r1;
        state[4 * col + 2] = r2;
        state[4 * col + 3] = r3;
    }
}

void AES128::addRoundKey(uint8_t state[16], int round) const {
    for (int i = 0; i < 16; ++i) {
        state[i] = static_cast<uint8_t>(state[i] ^ roundKeys_[round][i]);
    }
}

void AES128::encryptBlock(const uint8_t input[16], uint8_t output[16]) const {
    uint8_t state[16];
    for (int i = 0; i < 16; ++i) {
        state[i] = input[i];
    }

    addRoundKey(state, 0);

    for (int round = 1; round <= 9; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, round);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, 10);

    for (int i = 0; i < 16; ++i) {
        output[i] = state[i];
    }
}
