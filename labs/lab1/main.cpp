// ============================================================
//  Лабораторная работа №1
//  Вариант 6: СТБ 34.101.31 (БелТ), p(x)=0x169
//  GCM, Constant-time проверка имитовставки Tag
//  Один модуль, C++17, без сторонних крипто-библиотек.
// ============================================================
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <array>
#include <vector>
#include <algorithm>

// ============================================================
//  МОДУЛЬ 1. Универсальный калькулятор Галуа GF(2^8)
//  p_x — 9-битное представление полинома (например 0x169)
// ============================================================
class GaloisField {
public:
    explicit GaloisField(uint16_t p_x)
        : p_byte_(uint8_t(p_x & 0xFF)) {
        if ((p_x & 0x100) == 0)
            std::printf("Warning: p(x) degree != 8\n");
        buildSbox();
    }

    static uint8_t add(uint8_t a, uint8_t b) { return uint8_t(a ^ b); }

    // Умножение по модулю p(x), constant-time (8 фикс. итераций)
    uint8_t mul(uint8_t a, uint8_t b) const {
        uint8_t res = 0;
        uint8_t aa  = a;
        uint8_t bb  = b;
        for (int i = 0; i < 8; ++i) {
            uint8_t mask = uint8_t(-(int8_t)(bb & 1));
            res ^= uint8_t(aa & mask);
            uint8_t hi = uint8_t(aa >> 7);
            aa = uint8_t(aa << 1);
            aa ^= uint8_t((-(int8_t)hi) & p_byte_);
            bb >>= 1;
        }
        return res;
    }

    // a^(2^8 - 2) = a^254, constant-time
    uint8_t inv(uint8_t a) const {
        if (a == 0) return 0;
        uint8_t x2   = mul(a, a);
        uint8_t x4   = mul(x2, x2);
        uint8_t x8   = mul(x4, x4);
        uint8_t x16  = mul(x8, x8);
        uint8_t x32  = mul(x16, x16);
        uint8_t x64  = mul(x32, x32);
        uint8_t x128 = mul(x64, x64);
        uint8_t r = x128;
        r = mul(r, x64);
        r = mul(r, x32);
        r = mul(r, x16);
        r = mul(r, x8);
        r = mul(r, x4);
        r = mul(r, x2);
        return r;
    }

    static uint8_t affineAES(uint8_t b) {
        uint8_t x = b;
        auto rotl8 = [](uint8_t v, int n) {
            return uint8_t((v << n) | (v >> (8 - n)));
        };
        uint8_t y = uint8_t(x ^ rotl8(x,1) ^ rotl8(x,2) ^ rotl8(x,3) ^ rotl8(x,4));
        return uint8_t(y ^ 0x63);
    }

    const std::array<uint8_t,256>& sbox() const { return sbox_; }

private:
    uint8_t p_byte_;
    std::array<uint8_t,256> sbox_{};

    void buildSbox() {
        for (int i = 0; i < 256; ++i)
            sbox_[i] = affineAES(inv(uint8_t(i)));
    }
};

// ============================================================
//  МОДУЛЬ 2. СТБ 34.101.31 («БелТ»)
// ============================================================
static const uint8_t BELT_H[256] = {
    0xB1,0x94,0xBA,0xC8,0x0A,0x08,0xF5,0x3B,0x36,0x6D,0x00,0x8E,0x58,0x4A,0x5D,0xE4,
    0x85,0x04,0xFA,0x9D,0x1B,0xB6,0xC7,0xAC,0x25,0x2E,0x72,0xC2,0x02,0xFD,0xCE,0x0D,
    0x5B,0xE3,0xD6,0x12,0x17,0xB9,0x61,0x81,0xFE,0x67,0x86,0xAD,0x71,0x6B,0x89,0x0B,
    0x5C,0xB0,0xC0,0xFF,0x33,0xC3,0x56,0xB8,0x35,0xC4,0x05,0xAE,0xD8,0xE0,0x7F,0x99,
    0xE1,0x2B,0xDC,0x1A,0xE2,0x82,0x57,0xEC,0x70,0x3F,0xCC,0xF0,0x95,0xEE,0x8D,0xF1,
    0xC1,0xAB,0x76,0x38,0x9F,0xE6,0x78,0xCA,0xF7,0xC6,0xF8,0x60,0xD5,0xBB,0x9C,0x4F,
    0xF3,0x3C,0x65,0x7B,0x63,0x7C,0x30,0x6A,0xDD,0x4E,0xA7,0x79,0x9E,0xB2,0x3D,0x31,
    0x3E,0x98,0xB5,0x6E,0x27,0xD3,0xBC,0xCF,0x59,0x1E,0x18,0x1F,0x4C,0x5A,0xB7,0x93,
    0xE9,0xDE,0xE7,0x2C,0x8F,0x0C,0x0F,0xA6,0x2D,0xDB,0x49,0xF4,0x6F,0x73,0x96,0x47,
    0x06,0x07,0x53,0x16,0xED,0x24,0x7A,0x37,0x39,0xCB,0xA3,0x83,0x03,0xA9,0x8B,0xF6,
    0x92,0xBD,0x9B,0x1C,0xE5,0xD1,0x41,0x01,0x54,0x45,0xFB,0xC9,0x5E,0x4D,0x0E,0xF2,
    0x68,0x20,0x80,0xAA,0x22,0x7D,0x64,0x2F,0x26,0x87,0xF9,0x34,0x90,0x40,0x55,0x11,
    0xBE,0x32,0x97,0x13,0x43,0xFC,0x9A,0x48,0xA0,0x2A,0x88,0x5F,0x19,0x4B,0x09,0xA1,
    0x7E,0xCD,0xA4,0xD0,0x15,0x44,0xAF,0x8C,0xA5,0x84,0x50,0xBF,0x66,0xD2,0xE8,0x8A,
    0xA2,0xD7,0x46,0x52,0x42,0xA8,0xDF,0xB3,0x69,0x74,0xC5,0x51,0xEB,0x23,0x29,0x21,
    0xD4,0xEF,0xD9,0xB4,0x3A,0x62,0x28,0x75,0x91,0x14,0x10,0xEA,0x77,0x6C,0xDA,0x1D
};

class Belt {
public:
    static constexpr int ROUNDS = 8;

    explicit Belt(const uint8_t key[32]) {
        for (int i = 0; i < 8; ++i)
            K_[i] = loadBE32(key + 4*i);
    }

    void encryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        uint32_t a = loadBE32(in + 0);
        uint32_t b = loadBE32(in + 4);
        uint32_t c = loadBE32(in + 8);
        uint32_t d = loadBE32(in + 12);

        for (int r = 1; r <= ROUNDS; ++r) {
            uint32_t k0 = K_[(7*r - 7) & 7];
            uint32_t k1 = K_[(7*r - 6) & 7];
            uint32_t k2 = K_[(7*r - 5) & 7];
            uint32_t k3 = K_[(7*r - 4) & 7];
            uint32_t k4 = K_[(7*r - 3) & 7];
            uint32_t k5 = K_[(7*r - 2) & 7];
            uint32_t k6 = K_[(7*r - 1) & 7];

            b ^= G5 (a + k0);
            c ^= G21(d + k1);
            a -= G13(b + k2);
            d += G21(c + k3) ^ uint32_t(r);
            c ^= G5 (b + k4);
            a ^= G13(d + k5);
            b -= G21(c + k6);
        }
        storeBE32(a, out + 0);
        storeBE32(b, out + 4);
        storeBE32(c, out + 8);
        storeBE32(d, out + 12);
    }

    void decryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        uint32_t a = loadBE32(in + 0);
        uint32_t b = loadBE32(in + 4);
        uint32_t c = loadBE32(in + 8);
        uint32_t d = loadBE32(in + 12);

        for (int r = ROUNDS; r >= 1; --r) {
            uint32_t k0 = K_[(7*r - 7) & 7];
            uint32_t k1 = K_[(7*r - 6) & 7];
            uint32_t k2 = K_[(7*r - 5) & 7];
            uint32_t k3 = K_[(7*r - 4) & 7];
            uint32_t k4 = K_[(7*r - 3) & 7];
            uint32_t k5 = K_[(7*r - 2) & 7];
            uint32_t k6 = K_[(7*r - 1) & 7];

            b += G21(c + k6);
            a ^= G13(d + k5);
            c ^= G5 (b + k4);
            d -= G21(c + k3) ^ uint32_t(r);
            a += G13(b + k2);
            c ^= G21(d + k1);
            b ^= G5 (a + k0);
        }
        storeBE32(a, out + 0);
        storeBE32(b, out + 4);
        storeBE32(c, out + 8);
        storeBE32(d, out + 12);
    }

private:
    uint32_t K_[8];

    static uint32_t loadBE32(const uint8_t* p) {
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
             | (uint32_t(p[2]) << 8)  |  uint32_t(p[3]);
    }
    static void storeBE32(uint32_t v, uint8_t* p) {
        p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16);
        p[2] = uint8_t(v >> 8);  p[3] = uint8_t(v);
    }

    static uint8_t subByte(uint8_t x) { return BELT_H[x]; }

    static uint32_t S(uint32_t x) {
        return (uint32_t(subByte(uint8_t(x >> 24))) << 24)
             | (uint32_t(subByte(uint8_t(x >> 16))) << 16)
             | (uint32_t(subByte(uint8_t(x >>  8))) <<  8)
             |  uint32_t(subByte(uint8_t(x)));
    }
    static uint32_t rotl32(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }
    static uint32_t G5 (uint32_t x) { return rotl32(S(x),  5); }
    static uint32_t G13(uint32_t x) { return rotl32(S(x), 13); }
    static uint32_t G21(uint32_t x) { return rotl32(S(x), 21); }
};

// ============================================================
//  МОДУЛЬ 3. AEAD GCM + Constant-time
//  GF(2^128), f(x) = x^128 + x^7 + x^2 + x + 1
//  Шифрование блока передаётся через шаблонный параметр (без std::function).
// ============================================================
template <class Cipher>
class GCM {
public:
    GCM(const Cipher& c) : cipher_(c) {
        uint8_t zero[16] = {0};
        cipher_.encryptBlock(zero, H_);
    }

    void seal(const std::vector<uint8_t>& aad,
              const std::vector<uint8_t>& pt,
              const std::vector<uint8_t>& iv,
              std::vector<uint8_t>& out_ct,
              uint8_t out_tag[16]) const
    {
        // ---- J0 ----
        uint8_t J0[16];
        if (iv.size() == 12) {
            std::memcpy(J0, iv.data(), 12);
            J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
        } else {
            // GHASH_H( IV || 0^s || [0]_64 || [len(IV)]_64 )
            std::vector<uint8_t> ivPadded;
            if (!iv.empty()) {
                size_t pad = (16 - (iv.size() % 16)) % 16;
                ivPadded.assign(iv.begin(), iv.end());
                ivPadded.insert(ivPadded.end(), pad, 0);
            }
            uint8_t lenBlock[16] = {0};
            storeBE64(uint64_t(iv.size()) * 8, lenBlock + 8);

            std::vector<uint8_t> buf;
            buf.insert(buf.end(), ivPadded.begin(), ivPadded.end());
            buf.insert(buf.end(), lenBlock, lenBlock + 16);
            ghash(buf.data(), buf.size(), J0);
        }

        // ---- CTR ----
        out_ct.assign(pt.size(), 0);
        uint8_t counter[16];
        std::memcpy(counter, J0, 16);
        size_t off = 0;
        while (off < pt.size()) {
            inc32(counter);
            uint8_t ks[16];
            cipher_.encryptBlock(counter, ks);
            size_t n = std::min<size_t>(16, pt.size() - off);
            for (size_t i = 0; i < n; ++i)
                out_ct[off + i] = uint8_t(pt[off + i] ^ ks[i]);
            off += n;
        }

        // ---- GHASH по AAD и C ----
        uint8_t S[16];
        {
            std::vector<uint8_t> buf;
            // AAD, дополненный нулями
            if (!aad.empty()) {
                buf.insert(buf.end(), aad.begin(), aad.end());
                size_t pad = (16 - (aad.size() % 16)) % 16;
                buf.insert(buf.end(), pad, 0);
            }
            // C, дополненный нулями
            if (!out_ct.empty()) {
                buf.insert(buf.end(), out_ct.begin(), out_ct.end());
                size_t pad = (16 - (out_ct.size() % 16)) % 16;
                buf.insert(buf.end(), pad, 0);
            }
            // длины (в битах): AAD, C
            uint8_t lenBlock[16];
            storeBE64(uint64_t(aad.size()) * 8, lenBlock);
            storeBE64(uint64_t(out_ct.size()) * 8, lenBlock + 8);
            buf.insert(buf.end(), lenBlock, lenBlock + 16);

            ghash(buf.data(), buf.size(), S);
        }

        // ---- T = GHASH XOR E_K(J0) ----
        uint8_t ej0[16];
        cipher_.encryptBlock(J0, ej0);
        for (int i = 0; i < 16; ++i)
            out_tag[i] = uint8_t(S[i] ^ ej0[i]);
    }

    // Constant-time проверка тега
    static bool verifyTagCT(const uint8_t computed[16], const uint8_t received[16]) {
        uint8_t acc = 0;
        for (int i = 0; i < 16; ++i)
            acc |= uint8_t(computed[i] ^ received[i]);
        return acc == 0;
    }

private:
    const Cipher& cipher_;
    uint8_t H_[16];

    static void storeBE64(uint64_t v, uint8_t* p) {
        for (int i = 0; i < 8; ++i)
            p[i] = uint8_t(v >> (56 - 8*i));
    }

    static void inc32(uint8_t c[16]) {
        for (int i = 15; i >= 12; --i) {
            if (++c[i] != 0) break;
        }
    }

    // Умножение в GF(2^128), constant-time (128 итераций, без ветвлений)
    static void gf128Mul(const uint8_t X[16], const uint8_t V[16], uint8_t Z[16]) {
        uint8_t z[16] = {0};
        uint8_t v[16];
        std::memcpy(v, V, 16);
        for (int i = 0; i < 128; ++i) {
            uint8_t bit  = uint8_t((X[i >> 3] >> (7 - (i & 7))) & 1);
            uint8_t mask = uint8_t(-(int8_t)bit);
            for (int j = 0; j < 16; ++j)
                z[j] ^= uint8_t(v[j] & mask);

            uint8_t lsb = uint8_t(v[15] & 1);
            uint8_t carry = 0;
            for (int j = 0; j < 16; ++j) {
                uint8_t nc = uint8_t(v[j] & 1);
                v[j] = uint8_t((v[j] >> 1) | (carry << 7));
                carry = nc;
            }
            v[0] ^= uint8_t(0xE1 & uint8_t(-(int8_t)lsb));
        }
        std::memcpy(Z, z, 16);
    }

    // GHASH: Y_i = (Y_{i-1} XOR X_i) * H, X_i — блоки по 16 байт
    void ghash(const uint8_t* data, size_t len, uint8_t out[16]) const {
        uint8_t Y[16] = {0};
        for (size_t off = 0; off < len; off += 16) {
            for (int i = 0; i < 16; ++i)
                Y[i] ^= data[off + i];
            uint8_t tmp[16];
            gf128Mul(Y, H_, tmp);
            std::memcpy(Y, tmp, 16);
        }
        std::memcpy(out, Y, 16);
    }
};

// ============================================================
//  Демонстрация
// ============================================================
static void printHex(const char* label, const uint8_t* p, size_t n) {
    std::printf("%s", label);
    for (size_t i = 0; i < n; ++i) std::printf("%02X", p[i]);
    std::printf("\n");
}

int main() {
    std::printf("=== Лабораторная работа №1. Вариант 6 ===\n\n");

    // ---------- Модуль 1 ----------
    std::printf("--- Модуль 1: Galois Field GF(2^8), p(x)=0x169 ---\n");
    GaloisField gf(0x169);
    uint8_t a = 0x57, b = 0x83;
    uint8_t prod = gf.mul(a, b);
    uint8_t inv  = gf.inv(a);
    uint8_t chk  = gf.mul(a, inv);
    std::printf("mul(0x%02X, 0x%02X) = 0x%02X\n", a, b, prod);
    std::printf("inv(0x%02X)         = 0x%02X\n", a, inv);
    std::printf("a * inv            = 0x%02X (ожидается 0x01)\n", chk);
    std::printf("S[0x00]=0x%02X S[0x01]=0x%02X (AES-построение)\n",
                gf.sbox()[0x00], gf.sbox()[0x01]);
    std::printf("\n");

    // ---------- Модуль 2 ----------
    std::printf("--- Модуль 2: СТБ 34.101.31 (БелТ) ---\n");
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = uint8_t(i);
    Belt belt(key);

    uint8_t pt[16];
    for (int i = 0; i < 16; ++i) pt[i] = uint8_t(i);
    uint8_t ct[16], dt[16];
    belt.encryptBlock(pt, ct);
    belt.decryptBlock(ct, dt);

    printHex("Key      : ", key, 32);
    printHex("Plain    : ", pt, 16);
    printHex("Cipher   : ", ct, 16);
    printHex("Decipher : ", dt, 16);
    std::printf("Round-trip: %s\n\n",
                std::memcmp(pt, dt, 16) == 0 ? "OK" : "FAILED");

    // ---------- Модуль 3 ----------
    std::printf("--- Модуль 3: AEAD GCM + Constant-time ---\n");
    GCM<Belt> gcm(belt);

    std::vector<uint8_t> aad  = {'A','A','D','-','d','a','t','a'};
    std::vector<uint8_t> text = {'H','e','l','l','o',' ','G','C','M','!'};
    std::vector<uint8_t> iv(12, 0xAB);

    std::vector<uint8_t> ct2;
    uint8_t tag[16];
    gcm.seal(aad, text, iv, ct2, tag);

    printHex("AAD      : ", aad.data(),  aad.size());
    printHex("Plain    : ", text.data(), text.size());
    printHex("IV       : ", iv.data(),   iv.size());
    printHex("Cipher   : ", ct2.data(),  ct2.size());
    printHex("Tag      : ", tag, 16);

    uint8_t good[16], bad[16];
    std::memcpy(good, tag, 16);
    std::memcpy(bad,  tag, 16);
    bad[15] ^= 0x01;

    std::printf("verifyTagCT(tag, tag)      = %s\n",
                GCM<Belt>::verifyTagCT(tag, good) ? "true" : "false");
    std::printf("verifyTagCT(tag, tag^bit)  = %s\n",
                GCM<Belt>::verifyTagCT(tag, bad)  ? "true" : "false");

    return 0;
}