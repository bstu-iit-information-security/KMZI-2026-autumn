#include "gcm.h"
#include <cstring>

namespace lab1 {

    // GF(2^128)-умножение по модулю f(x)=x^128+x^7+x^2+x+1.
    // Константы: R = 0xE1 в старшем байте (NIST SP 800-38D).
    // Constant-time: ровно 128 итераций, без if по данным.
    void gf128_mul(const uint8_t X[16], const uint8_t Y[16], uint8_t Z[16]) {
        uint8_t V[16];
        std::memcpy(V, X, 16);
        std::memset(Z, 0, 16);

        for (int i = 0; i < 128; ++i) {
            uint8_t ybit = static_cast<uint8_t>((Y[i >> 3] >> (7 - (i & 7))) & 1);
            uint8_t mask = static_cast<uint8_t>(-ybit);
            for (int j = 0; j < 16; ++j) Z[j] ^= static_cast<uint8_t>(V[j] & mask);

            uint8_t lsb = static_cast<uint8_t>(V[15] & 1);
            for (int j = 15; j > 0; --j) {
                V[j] = static_cast<uint8_t>((V[j] >> 1) | (V[j - 1] << 7));
            }
            V[0] = static_cast<uint8_t>(V[0] >> 1);
            V[0] ^= static_cast<uint8_t>(0xE1 & static_cast<uint8_t>(-lsb));
        }
    }

    // GHASH:  Y_0 = 0;  Y_i = (Y_{i-1} ⊕ X_i) · H
    void ghash(const uint8_t H[16],
        const uint8_t* aad, size_t aad_len,
        const uint8_t* ciph, size_t ciph_len,
        uint8_t out[16]) {
        uint8_t Y[16] = { 0 };
        uint8_t block[16];

        // AAD
        size_t n = (aad_len + 15) / 16;
        for (size_t i = 0; i < n; ++i) {
            std::memset(block, 0, 16);
            size_t rem = aad_len - i * 16;
            size_t cp = (rem < 16) ? rem : 16;
            std::memcpy(block, aad + i * 16, cp);
            for (int j = 0; j < 16; ++j) Y[j] ^= block[j];
            uint8_t t[16];
            gf128_mul(Y, H, t);
            std::memcpy(Y, t, 16);
        }

        // Ciphertext
        n = (ciph_len + 15) / 16;
        for (size_t i = 0; i < n; ++i) {
            std::memset(block, 0, 16);
            size_t rem = ciph_len - i * 16;
            size_t cp = (rem < 16) ? rem : 16;
            std::memcpy(block, ciph + i * 16, cp);
            for (int j = 0; j < 16; ++j) Y[j] ^= block[j];
            uint8_t t[16];
            gf128_mul(Y, H, t);
            std::memcpy(Y, t, 16);
        }

        // Блок длин: len(AAD)·8 || len(C)·8 (big-endian, 64+64 бита)
        uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
        uint64_t c_bits = static_cast<uint64_t>(ciph_len) * 8;
        for (int i = 0; i < 8; ++i) {
            block[i] = static_cast<uint8_t>((aad_bits >> (56 - i * 8)) & 0xFF);
            block[8 + i] = static_cast<uint8_t>((c_bits >> (56 - i * 8)) & 0xFF);
        }
        for (int j = 0; j < 16; ++j) Y[j] ^= block[j];
        uint8_t t[16];
        gf128_mul(Y, H, t);
        std::memcpy(out, t, 16);
    }

    // Constant-time сравнение: без early exit.
    bool constantTimeCompare(const uint8_t* a, const uint8_t* b, size_t len) {
        uint8_t diff = 0;
        for (size_t i = 0; i < len; ++i) {
            diff |= static_cast<uint8_t>(a[i] ^ b[i]);
        }
        return diff == 0;
    }

    GCM::GCM(const uint8_t key[16], uint16_t gf_poly)
        : gf_(gf_poly), aes_(key, gf_) {
    }

    void GCM::encrypt(const uint8_t iv[12],
        const uint8_t* aad, size_t aad_len,
        const uint8_t* pt, size_t pt_len,
        uint8_t* ct, uint8_t tag[16]) {
        // H = E_K(0^128)
        uint8_t zero[16] = { 0 };
        uint8_t H[16];
        aes_.encryptBlock(zero, H);

        // J0 = IV || 0^31 || 1
        uint8_t J0[16];
        std::memcpy(J0, iv, 12);
        J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

        // CTR-шифрование
        uint8_t counter[16];
        std::memcpy(counter, J0, 16);
        size_t nblocks = (pt_len + 15) / 16;
        for (size_t i = 0; i < nblocks; ++i) {
            for (int j = 15; j >= 12; --j) {
                if (++counter[j] != 0) break;
            }
            uint8_t ks[16];
            aes_.encryptBlock(counter, ks);
            size_t rem = pt_len - i * 16;
            size_t cp = (rem < 16) ? rem : 16;
            for (size_t j = 0; j < cp; ++j) {
                ct[i * 16 + j] = static_cast<uint8_t>(pt[i * 16 + j] ^ ks[j]);
            }
        }

        // GHASH
        uint8_t S[16];
        ghash(H, aad, aad_len, ct, pt_len, S);

        // Tag = GHASH ⊕ E_K(J0)
        uint8_t EJ0[16];
        aes_.encryptBlock(J0, EJ0);
        for (int i = 0; i < 16; ++i) tag[i] = static_cast<uint8_t>(S[i] ^ EJ0[i]);
    }

    bool GCM::decrypt(const uint8_t iv[12],
        const uint8_t* aad, size_t aad_len,
        const uint8_t* ct, size_t ct_len,
        uint8_t* pt, const uint8_t tag[16]) {
        uint8_t zero[16] = { 0 };
        uint8_t H[16];
        aes_.encryptBlock(zero, H);

        uint8_t J0[16];
        std::memcpy(J0, iv, 12);
        J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

        // Проверка тега
        uint8_t S[16];
        ghash(H, aad, aad_len, ct, ct_len, S);
        uint8_t EJ0[16];
        aes_.encryptBlock(J0, EJ0);
        uint8_t computed[16];
        for (int i = 0; i < 16; ++i) computed[i] = static_cast<uint8_t>(S[i] ^ EJ0[i]);
        bool ok = constantTimeCompare(computed, tag, 16);

        // Расшифрование CTR
        uint8_t counter[16];
        std::memcpy(counter, J0, 16);
        size_t nblocks = (ct_len + 15) / 16;
        for (size_t i = 0; i < nblocks; ++i) {
            for (int j = 15; j >= 12; --j) {
                if (++counter[j] != 0) break;
            }
            uint8_t ks[16];
            aes_.encryptBlock(counter, ks);
            size_t rem = ct_len - i * 16;
            size_t cp = (rem < 16) ? rem : 16;
            for (size_t j = 0; j < cp; ++j) {
                pt[i * 16 + j] = static_cast<uint8_t>(ct[i * 16 + j] ^ ks[j]);
            }
        }
        return ok;
    }

} // namespace lab1