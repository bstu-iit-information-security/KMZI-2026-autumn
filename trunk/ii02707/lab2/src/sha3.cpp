#include "sha3.hpp"
#include <cstring>
#include <algorithm>

static inline uint64_t rotl64(uint64_t x, int n) {
    n &= 63;
    if (n == 0) return x;
    return (x << n) | (x >> (64 - n));
}

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int ROT[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

static void keccak_f1600(uint64_t st[25]) {
    for (int round = 0; round < 24; ++round) {
        uint64_t C[5];
        for (int x = 0; x < 5; ++x)
            C[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20];
        uint64_t D[5];
        for (int x = 0; x < 5; ++x)
            D[x] = C[(x+4)%5] ^ rotl64(C[(x+1)%5], 1);
        for (int i = 0; i < 25; ++i)
            st[i] ^= D[i % 5];

        uint64_t T[25];
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y) {
                int nx = y;
                int ny = (2*x + 3*y) % 5;
                T[nx + 5*ny] = rotl64(st[x + 5*y], ROT[x + 5*y]);
            }

        for (int y = 0; y < 5; ++y)
            for (int x = 0; x < 5; ++x)
                st[x + 5*y] = T[x + 5*y] ^ ((~T[(x+1)%5 + 5*y]) & T[(x+2)%5 + 5*y]);

        st[0] ^= RC[round];
    }
}

SHA3_256::SHA3_256() { reset(); }

void SHA3_256::reset() {
    std::memset(state_, 0, sizeof(state_));
    std::memset(buf_, 0, sizeof(buf_));
    buf_len_ = 0;
}

void SHA3_256::absorb_block() {
    for (size_t i = 0; i < RATE / 8; ++i) {
        uint64_t w = 0;
        std::memcpy(&w, buf_ + i*8, 8);
        state_[i] ^= w;
    }
    keccak_f1600(state_);
}

void SHA3_256::update(const uint8_t* data, size_t len) {
    if (len == 0 || data == nullptr) return;
    
    while (len > 0) {
        size_t space = RATE - buf_len_;
        size_t take  = std::min(space, len);
        std::memcpy(buf_ + buf_len_, data, take);
        buf_len_ += take;
        data += take;
        len  -= take;
        if (buf_len_ == RATE) {
            absorb_block();
            buf_len_ = 0;
        }
    }
}

void SHA3_256::final(uint8_t out[HASH_LEN]) {
    std::memset(buf_ + buf_len_, 0, RATE - buf_len_);
    buf_[buf_len_] = 0x06;
    buf_[RATE - 1] |= 0x80;
    absorb_block();

    std::memcpy(out, state_, HASH_LEN);
    reset();
}

std::array<uint8_t, SHA3_256::HASH_LEN>
SHA3_256::hash(const uint8_t* data, size_t len) {
    SHA3_256 ctx;
    ctx.update(data, len);
    return ctx.finalize();
}