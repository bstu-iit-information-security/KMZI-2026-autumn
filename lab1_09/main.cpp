#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>

using namespace std;

// ============================================================
// МОДУЛЬ 1. Калькулятор полей Галуа GF(2^8)
// ============================================================
struct GF28Calculator {
    static unsigned char multiply(unsigned char a, unsigned char b, uint16_t p_x) {
        unsigned char r = 0, poly = p_x & 0xFF;
        for (int i = 0; i < 8; ++i) {
            r ^= a & -(b & 1);
            a = (a << 1) ^ (-(a >> 7) & poly);
            b >>= 1;
        }
        return r;
    }

    // Обратный элемент a^254 mod p(x) по Ферма (0x00 -> 0x00)
    static unsigned char inverse(unsigned char a, uint16_t p_x) {
        if (!a) return 0;
        unsigned char x2 = multiply(a, a, p_x), x4 = multiply(x2, x2, p_x);
        unsigned char x8 = multiply(x4, x4, p_x), x16 = multiply(x8, x8, p_x);
        unsigned char x32 = multiply(x16, x16, p_x), x64 = multiply(x32, x32, p_x);
        unsigned char x128 = multiply(x64, x64, p_x);

        return multiply(multiply(multiply(multiply(multiply(multiply(x2, x4, p_x), x8, p_x), x16, p_x), x32, p_x), x64, p_x), x128, p_x);
    }

    static void generate_tables(uint16_t p_x, unsigned char sbox[256], unsigned char rcon[11]) {
        for (int i = 0; i < 256; ++i) {
            unsigned char x = inverse(i, p_x);
            sbox[i] = x ^ (x<<1 | x>>7) ^ (x<<2 | x>>6) ^ (x<<3 | x>>5) ^ (x<<4 | x>>4) ^ 0x63;
        }
        rcon[1] = 0x01;
        for (int i = 2; i <= 10; ++i) rcon[i] = multiply(rcon[i - 1], 0x02, p_x);
    }
};

// ============================================================
// МОДУЛЬ 2. Блочный шифр AES-128
// ============================================================
class AES128 {
private:
    uint16_t p_x;
    unsigned char sbox[256], rcon[11], rk[176];

public:
    explicit AES128(uint16_t poly) : p_x(poly) {
        GF28Calculator::generate_tables(p_x, sbox, rcon);
    }

    void expand_key(const unsigned char key[16]) {
        memcpy(rk, key, 16);
        for (int i = 16; i < 176; i += 4) {
            unsigned char t[4] = { rk[i-4], rk[i-3], rk[i-2], rk[i-1] };
            if (i % 16 == 0) {
                unsigned char tmp = t[0];
                t[0] = sbox[t[1]] ^ rcon[i / 16];
                t[1] = sbox[t[2]];
                t[2] = sbox[t[3]];
                t[3] = sbox[tmp];
            }
            for (int j = 0; j < 4; ++j) rk[i + j] = rk[i - 16 + j] ^ t[j];
        }
    }

    void encrypt_block(const unsigned char in[16], unsigned char out[16]) const {
        unsigned char s[16], t[16];
        memcpy(s, in, 16);

        for (int i = 0; i < 16; ++i) s[i] ^= rk[i];

        for (int round = 1; round <= 10; ++round) {
            for (int i = 0; i < 16; ++i) s[i] = sbox[s[i]];

            for (int r = 0; r < 4; ++r)
                for (int c = 0; c < 4; ++c) t[4 * c + r] = s[4 * ((c + r) % 4) + r];

            if (round < 10) { // MixColumns для раундов 1-9
                for (int c = 0; c < 4; ++c) {
                    unsigned char a0 = t[4*c], a1 = t[4*c+1], a2 = t[4*c+2], a3 = t[4*c+3];
                    s[4*c+0] = GF28Calculator::multiply(a0, 2, p_x) ^ GF28Calculator::multiply(a1, 3, p_x) ^ a2 ^ a3;
                    s[4*c+1] = a0 ^ GF28Calculator::multiply(a1, 2, p_x) ^ GF28Calculator::multiply(a2, 3, p_x) ^ a3;
                    s[4*c+2] = a0 ^ a1 ^ GF28Calculator::multiply(a2, 2, p_x) ^ GF28Calculator::multiply(a3, 3, p_x);
                    s[4*c+3] = GF28Calculator::multiply(a0, 3, p_x) ^ a1 ^ a2 ^ GF28Calculator::multiply(a3, 2, p_x);
                }
            } else {
                memcpy(s, t, 16);
            }

            for (int i = 0; i < 16; ++i) s[i] ^= rk[round * 16 + i];
        }
        memcpy(out, s, 16);
    }
};

// ============================================================
// МОДУЛЬ 3. AEAD-режим GCM (SWAR + Constant-Time)
// ============================================================
class GCMMode {
private:
    static uint64_t ld_be64(const unsigned char* p) {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
        return v;
    }

    static void st_be64(unsigned char* p, uint64_t v) {
        for (int i = 7; i >= 0; --i) { p[i] = v; v >>= 8; }
    }

    // SWAR умножение в GF(2^128)
    static void gf128_mul_swar(uint64_t& xh, uint64_t& xl, uint64_t yh, uint64_t yl) {
        uint64_t zh = 0, zl = 0, vh = yh, vl = yl;
        for (int i = 0; i < 128; ++i) {
            uint64_t bit = (i < 64) ? ((xh >> (63 - i)) & 1) : ((xl >> (127 - i)) & 1);
            zh ^= vh & -bit;
            zl ^= vl & -bit;
            uint64_t rmask = -(vl & 1);
            vl = (vl >> 1) | (vh << 63);
            vh = (vh >> 1) ^ (0xE100000000000000ULL & rmask);
        }
        xh = zh; xl = zl;
    }

    static void process_ghash_data(const unsigned char* data, size_t len, uint64_t& yh, uint64_t& yl, uint64_t hh, uint64_t hl) {
        for (size_t i = 0; i < len; i += 16) {
            unsigned char b[16] = {0};
            memcpy(b, data + i, (len - i < 16) ? len - i : 16);
            yh ^= ld_be64(b); yl ^= ld_be64(b + 8);
            gf128_mul_swar(yh, yl, hh, hl);
        }
    }

    static void ghash(const unsigned char* aad, size_t alen, const unsigned char* ct, size_t clen, const unsigned char H[16], unsigned char out[16]) {
        uint64_t yh = 0, yl = 0, hh = ld_be64(H), hl = ld_be64(H + 8);
        process_ghash_data(aad, alen, yh, yl, hh, hl);
        process_ghash_data(ct, clen, yh, yl, hh, hl);

        unsigned char lb[16] = {0};
        st_be64(lb, alen * 8);
        st_be64(lb + 8, clen * 8);
        yh ^= ld_be64(lb); yl ^= ld_be64(lb + 8);
        gf128_mul_swar(yh, yl, hh, hl);

        st_be64(out, yh); st_be64(out + 8, yl);
    }

    static void inc32(unsigned char* b) {
        for (int i = 15; i >= 12; --i) if (++b[i]) break;
    }

public:
    static void encrypt(AES128 cipher, const unsigned char key[16], const unsigned char iv[12],
                        const unsigned char* aad, size_t alen, const unsigned char* pt, size_t plen,
                        unsigned char* ct, unsigned char tag[16]) {
        cipher.expand_key(key);
        unsigned char H[16] = {0}, J0[16] = {0}, CB[16], S[16], E0[16];
        cipher.encrypt_block(H, H);

        memcpy(J0, iv, 12); J0[15] = 1;
        memcpy(CB, J0, 16); inc32(CB);

        for (size_t i = 0; i < plen; i += 16) {
            unsigned char g[16];
            cipher.encrypt_block(CB, g);
            size_t n = (plen - i < 16) ? plen - i : 16;
            for (size_t j = 0; j < n; ++j) ct[i + j] = pt[i + j] ^ g[j];
            inc32(CB);
        }

        ghash(aad, alen, ct, plen, H, S);
        cipher.encrypt_block(J0, E0);
        for (int j = 0; j < 16; ++j) tag[j] = S[j] ^ E0[j];
    }

    static bool decrypt(AES128 cipher, const unsigned char key[16], const unsigned char iv[12],
                        const unsigned char* aad, size_t alen, const unsigned char* ct, size_t clen,
                        const unsigned char tag[16], unsigned char* pt) {
        cipher.expand_key(key);
        unsigned char H[16] = {0}, J0[16] = {0}, S[16], E0[16], expect[16], CB[16];
        cipher.encrypt_block(H, H);

        memcpy(J0, iv, 12); J0[15] = 1;
        ghash(aad, alen, ct, clen, H, S);
        cipher.encrypt_block(J0, E0);

        // Constant-time проверка
        unsigned char diff = 0;
        for (int j = 0; j < 16; ++j) {
            expect[j] = S[j] ^ E0[j];
            diff |= expect[j] ^ tag[j];
        }
        if (diff != 0) return false;

        memcpy(CB, J0, 16); inc32(CB);
        for (size_t i = 0; i < clen; i += 16) {
            unsigned char g[16];
            cipher.encrypt_block(CB, g);
            size_t n = (clen - i < 16) ? clen - i : 16;
            for (size_t j = 0; j < n; ++j) pt[i + j] = ct[i + j] ^ g[j];
            inc32(CB);
        }
        return true;
    }
};

// ============================================================
// Проверка
// ============================================================
void print_bytes(const char* label, const unsigned char* data, size_t len) {
    cout << label << ": ";
    for (size_t i = 0; i < len; ++i)
        cout << hex << uppercase << setw(2) << setfill('0') << (int)data[i];
    cout << dec << endl;
}

int main() {
    AES128 aes(0x1F5); // Вариант 9

    unsigned char key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    unsigned char iv[12]  = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
    unsigned char aad[16] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99};
    unsigned char pt[32]  = {0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,0x90,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x00,
                             0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
    unsigned char ct[32], tag[16], dec[32];

    GCMMode::encrypt(aes, key, iv, aad, 16, pt, 32, ct, tag);
    print_bytes("Ciphertext", ct, 32);
    print_bytes("Tag", tag, 16);

    bool ok = GCMMode::decrypt(aes, key, iv, aad, 16, ct, 32, tag, dec);
    cout << "Decrypt: " << (ok ? "OK" : "FAIL") << endl;

    return 0;
}