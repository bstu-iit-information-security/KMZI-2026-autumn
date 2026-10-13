#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace sha3 {

constexpr std::size_t RATE = 136;
constexpr std::size_t DIGEST = 32;

inline std::uint64_t rotl64(std::uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

inline void keccakf(std::uint64_t st[25]) {
    static const std::uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
    static const int ROT[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                                27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
    static const int PI[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                               15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};
    for (int round = 0; round < 24; ++round) {
        std::uint64_t bc[5];
        for (int i = 0; i < 5; ++i) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for (int i = 0; i < 5; ++i) {
            std::uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        std::uint64_t t = st[1];
        for (int i = 0; i < 24; ++i) {
            int j = PI[i];
            std::uint64_t tmp = st[j];
            st[j] = rotl64(t, ROT[i]);
            t = tmp;
        }
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; ++i) bc[i] = st[j + i];
            for (int i = 0; i < 5; ++i) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }
        st[0] ^= RC[round];
    }
}

inline void sha3_256(std::uint8_t out[DIGEST], const std::uint8_t* data, std::size_t len) {
    std::uint64_t st[25];
    std::memset(st, 0, sizeof(st));
    std::uint8_t* sb = reinterpret_cast<std::uint8_t*>(st);
    std::size_t off = 0;
    while (len - off >= RATE) {
        for (std::size_t i = 0; i < RATE; ++i) sb[i] ^= data[off + i];
        keccakf(st);
        off += RATE;
    }
    std::uint8_t block[RATE];
    std::memset(block, 0, sizeof(block));
    std::size_t rem = len - off;
    if (rem != 0) std::memcpy(block, data + off, rem);
    block[rem] ^= 0x06;
    block[RATE - 1] ^= 0x80;
    for (std::size_t i = 0; i < RATE; ++i) sb[i] ^= block[i];
    keccakf(st);
    std::memcpy(out, sb, DIGEST);
}

}
