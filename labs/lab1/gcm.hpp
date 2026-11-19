
#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include "aes128.hpp"

namespace gcm {

struct U128 {
    uint64_t hi, lo;
};

inline U128 load_be(const uint8_t p[16]) {
    U128 r{0, 0};
    for (int i = 0; i < 8; ++i) {
        r.hi = (r.hi << 8) | p[i];
        r.lo = (r.lo << 8) | p[8 + i];
    }
    return r;
}

inline void store_be(const U128& v, uint8_t p[16]) {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<uint8_t>(v.hi >> (56 - 8 * i));
        p[8 + i] = static_cast<uint8_t>(v.lo >> (56 - 8 * i));
    }
}

// Умножение в GF(2^128) (битовый порядок GCM: старший бит байта 0 — коэффициент x^0).
// Редукционная константа 0xE1 << 120 соответствует f(x).
inline U128 gf128_mul(const U128& x, const U128& y) {
    U128 z{0, 0}, v = y;
    for (int i = 0; i < 128; ++i) {
        const uint64_t bit = (i < 64) ? ((x.hi >> (63 - i)) & 1u) : ((x.lo >> (127 - i)) & 1u);
        const uint64_t m = 0u - bit;
        z.hi ^= v.hi & m;
        z.lo ^= v.lo & m;
        const uint64_t lsb = v.lo & 1u;
        v.lo = (v.lo >> 1) | (v.hi << 63);
        v.hi >>= 1;
        v.hi ^= 0xE100000000000000ULL & (0u - lsb);
    }
    return z;
}

// Сравнение за константное время: ВСЕ байты обрабатываются всегда,
// разности накапливаются в аккумуляторе, решение принимается один раз в конце.
// (Используется OR-накопление: XOR-накопление из методички может обнулиться
//  при двух одинаковых разностях в разных байтах.)
inline bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint32_t acc = 0;
    for (size_t i = 0; i < n; ++i) acc |= static_cast<uint32_t>(a[i] ^ b[i]);
    return ((acc - 1u) >> 31) != 0;  // 1 тогда и только тогда, когда acc == 0
}

class Gcm {
public:
    explicit Gcm(const Aes128& cipher) : aes_(cipher) {
        uint8_t zero[16] = {0}, h[16];
        aes_.encrypt_block(zero, h);  // H = E_K(0^128)
        H_ = load_be(h);
    }

    // Зашифрование: C = P xor CTR-гамма, tag = GHASH xor E_K(J0).
    void encrypt(const uint8_t iv[12], const uint8_t* aad, size_t aad_len,
                 const uint8_t* pt, size_t len, uint8_t* ct, uint8_t tag[16]) const {
        ctr_xor(iv, pt, len, ct);
        compute_tag(iv, aad, aad_len, ct, len, tag);
    }

    // Расшифрование с проверкой. При неверном теге открытый текст зануляется,
    // чтобы не отдавать непроверенные данные; время работы не зависит от результата сравнения.
    bool decrypt(const uint8_t iv[12], const uint8_t* aad, size_t aad_len,
                 const uint8_t* ct, size_t len, const uint8_t tag[16], uint8_t* pt) const {
        uint8_t expected[16];
        compute_tag(iv, aad, aad_len, ct, len, expected);
        const bool ok = ct_equal(expected, tag, 16);
        ctr_xor(iv, ct, len, pt);
        const uint8_t wipe = static_cast<uint8_t>(0u - static_cast<uint32_t>(ok ? 0 : 1));
        for (size_t i = 0; i < len; ++i) pt[i] = static_cast<uint8_t>(pt[i] & ~wipe);
        return ok;
    }

private:
    static void inc32(uint8_t cb[16]) {
        uint32_t c = (static_cast<uint32_t>(cb[12]) << 24) | (static_cast<uint32_t>(cb[13]) << 16) |
                     (static_cast<uint32_t>(cb[14]) << 8) | cb[15];
        ++c;
        cb[12] = static_cast<uint8_t>(c >> 24);
        cb[13] = static_cast<uint8_t>(c >> 16);
        cb[14] = static_cast<uint8_t>(c >> 8);
        cb[15] = static_cast<uint8_t>(c);
    }

    // CB_i = IV || counter32(i); данные шифруются, начиная со счётчика 2 (счётчик 1 = J0).
    void ctr_xor(const uint8_t iv[12], const uint8_t* in, size_t len, uint8_t* out) const {
        uint8_t cb[16], ks[16];
        for (int i = 0; i < 12; ++i) cb[i] = iv[i];
        cb[12] = 0; cb[13] = 0; cb[14] = 0; cb[15] = 1;
        for (size_t off = 0; off < len; off += 16) {
            inc32(cb);
            aes_.encrypt_block(cb, ks);
            const size_t n = (len - off < 16) ? (len - off) : 16;
            for (size_t i = 0; i < n; ++i) out[off + i] = static_cast<uint8_t>(in[off + i] ^ ks[i]);
        }
    }

    U128 ghash_update(U128 y, const uint8_t* data, size_t len) const {
        for (size_t off = 0; off < len; off += 16) {
            uint8_t blk[16] = {0};
            const size_t n = (len - off < 16) ? (len - off) : 16;
            for (size_t i = 0; i < n; ++i) blk[i] = data[off + i];
            const U128 x = load_be(blk);
            y.hi ^= x.hi;
            y.lo ^= x.lo;
            y = gf128_mul(y, H_);  // Y_i = (Y_{i-1} xor X_i) * H
        }
        return y;
    }

    void compute_tag(const uint8_t iv[12], const uint8_t* aad, size_t aad_len,
                     const uint8_t* ct, size_t len, uint8_t tag[16]) const {
        U128 y{0, 0};
        y = ghash_update(y, aad, aad_len);
        y = ghash_update(y, ct, len);
        U128 lens{static_cast<uint64_t>(aad_len) * 8u, static_cast<uint64_t>(len) * 8u};
        y.hi ^= lens.hi;
        y.lo ^= lens.lo;
        y = gf128_mul(y, H_);

        uint8_t j0[16], ek[16], g[16];
        for (int i = 0; i < 12; ++i) j0[i] = iv[i];
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
        aes_.encrypt_block(j0, ek);
        store_be(y, g);
        for (int i = 0; i < 16; ++i) tag[i] = static_cast<uint8_t>(g[i] ^ ek[i]);
    }

    const Aes128& aes_;
    U128 H_{0, 0};
};

}  // namespace gcm
