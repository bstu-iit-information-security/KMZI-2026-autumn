#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>

class SHA512 {
private:
    uint64_t state[8];
    uint8_t  buffer[128];
    uint64_t bitlen[2]; // bitlen[0] = low 64 bits, bitlen[1] = high 64 bits

    static constexpr uint64_t K[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7bee0fee7ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baafcf3ULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0x9a30dce680e65525ULL, 0xa2c79265caf2d2ddULL, 0xa831c66d4a80e303ULL, 0xb53001121c4d3eb4ULL,
        0xc703518a4d2d6116ULL, 0xca6351e807051446ULL, 0xd65d0e7a1577a009ULL, 0xd807aa9803472f87ULL,
        0x03d652ed9a066923ULL, 0x0a149c30f40f09a5ULL, 0x211c470a256d0590ULL, 0x2e86d0800b73af19ULL,
        0x32cca05d80b6f958ULL, 0x3922201d1c810488ULL, 0x4896d88b48f6551bULL, 0x56a64cc085b1d3f9ULL,
        0x80352efc1fe28114ULL, 0x9818bc70d0f772a8ULL, 0xa552a41738722254ULL, 0xb972fb274f88414eULL,
        0xc469fbdc1968ed9cULL, 0xd0e83ef7741d729eULL, 0xd72be5f303253b7cULL, 0x06c8365287e0f2cbULL,
        0x10344b1c8e104111ULL, 0x181e353e8082088fULL, 0x290d2341d3c01f68ULL, 0x2e23292a83e051e8ULL,
        0x386b72f8832a514dULL, 0x39a1d4a08620e7e1ULL, 0x41f486121f151ad8ULL, 0x6e2f416489370fe4ULL,
        0x7877478d104595e1ULL, 0x818a7c29e71e3b00ULL, 0x8cd298f240e34c2dULL, 0x9320e8913988dbf2ULL,
        0xa7d8252243d48d08ULL, 0xb805a5a1f98a287cULL, 0xc1bfb038e12a84a2ULL, 0xe70ee802f01f0103ULL
    };

    static inline uint64_t rotr(uint64_t x, uint64_t n) { return (x >> n) | (x << (64 - n)); }
    static inline uint64_t sig0(uint64_t x) { return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7); }
    static inline uint64_t sig1(uint64_t x) { return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6); }
    static inline uint64_t SIG0(uint64_t x) { return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39); }
    static inline uint64_t SIG1(uint64_t x) { return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41); }

    void transform(const uint8_t* data) {
        uint64_t W[80];
        for (size_t i = 0; i < 16; ++i) {
            W[i] = 0;
            for (size_t j = 0; j < 8; ++j) W[i] = (W[i] << 8) | data[i * 8 + j];
        }
        for (size_t i = 16; i < 80; ++i)
            W[i] = sig1(W[i - 2]) + W[i - 7] + sig0(W[i - 15]) + W[i - 16];

        uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (size_t i = 0; i < 80; ++i) {
            uint64_t T1 = h + SIG1(e) + ((e & f) ^ (~e & g)) + K[i] + W[i];
            uint64_t T2 = SIG0(a) + ((a & b) ^ (a & c) ^ (b & c));
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

public:
    SHA512() { reset(); }

    void reset() {
        state[0] = 0x6a09e667f3bcc908ULL; state[1] = 0xbb67ae8584caa73bULL;
        state[2] = 0x3c6ef372fe94f82bULL; state[3] = 0xa54ff53a5f1d36f1ULL;
        state[4] = 0x510e527fea9419abULL; state[5] = 0x9b05688c2b3e6c1fULL;
        state[6] = 0x1f83d9abfb41bd6bULL; state[7] = 0x5be0cd19137e2179ULL;
        bitlen[0] = 0; bitlen[1] = 0;
    }

    // === ИСПРАВЛЕНО: устранён баг с (bitlen[0] & 0x3F8) == 1024 ===
    // Теперь корректно срабатывает на каждом блоке 1024 бит (128 байт),
    // а не только на первом.
    void update(const uint8_t* data, size_t len) {
        if (data == nullptr || len == 0) return;
        for (size_t i = 0; i < len; ++i) {
            buffer[(bitlen[0] >> 3) & 0x7F] = data[i];
            uint64_t old = bitlen[0];
            bitlen[0] += 8;
            if (bitlen[0] < old) bitlen[1]++; // перенос в старшее слово
            // Проверяем, что прошли ровно 1024 бита с начала блока
            if ((bitlen[0] & 1023ULL) == 0) {
                transform(buffer);
            }
        }
    }

    void final(uint8_t hash[64]) {
        size_t i = (bitlen[0] >> 3) & 0x7F;
        buffer[i++] = 0x80;
        if (i > 112) {
            while (i < 128) buffer[i++] = 0x00;
            transform(buffer);
            i = 0;
        }
        while (i < 112) buffer[i++] = 0x00;

        // Длина сообщения в битах — big-endian, 128 бит (16 байт)
        for (int j = 0; j < 8; ++j) buffer[112 + j] = (bitlen[1] >> (8 * (7 - j))) & 0xFF;
        for (int j = 0; j < 8; ++j) buffer[120 + j] = (bitlen[0] >> (8 * (7 - j))) & 0xFF;

        transform(buffer);

        for (i = 0; i < 8; ++i)
            for (int j = 0; j < 8; ++j)
                hash[i * 8 + j] = (state[i] >> (8 * (7 - j))) & 0xFF;
    }

    static void hash(const uint8_t* input, size_t len, uint8_t output[64]) {
        SHA512 ctx;
        ctx.update(input, len);
        ctx.final(output);
    }
};