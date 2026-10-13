#include <cstdint>
#include <cstdio>
#include <cstring>

namespace GF256 {

    static constexpr uint8_t P_BYTE = 0x4D;

    inline uint8_t add(uint8_t a, uint8_t b) {
        return (uint8_t)(a ^ b);
    }

    inline uint8_t multiply(uint8_t a, uint8_t b) {
        uint8_t result = 0;
        for (int i = 0; i < 8; ++i) {
            uint8_t mask = (uint8_t)(-(int)(b & 1));
            result ^= (uint8_t)(a & mask);
            uint8_t hi = (uint8_t)(-(int)(a >> 7));
            a = (uint8_t)((a << 1) ^ (P_BYTE & hi));
            b >>= 1;
        }
        return result;
    }

    inline uint8_t xtime(uint8_t b) {
        uint8_t hi = (uint8_t)(-(int)(b >> 7));
        return (uint8_t)((b << 1) ^ (P_BYTE & hi));
    }

    inline uint8_t inverse(uint8_t a) {
        uint8_t a2   = multiply(a,   a);
        uint8_t a4   = multiply(a2,  a2);
        uint8_t a8   = multiply(a4,  a4);
        uint8_t a16  = multiply(a8,  a8);
        uint8_t a32  = multiply(a16, a16);
        uint8_t a64  = multiply(a32, a32);
        uint8_t a128 = multiply(a64, a64);

        uint8_t r = a128;
        r = multiply(r, a64);
        r = multiply(r, a32);
        r = multiply(r, a16);
        r = multiply(r, a8);
        r = multiply(r, a4);
        r = multiply(r, a2);
        return r;
    }

    inline uint8_t rotl8(uint8_t x, int n) {
        return (uint8_t)((x << n) | (x >> (8 - n)));
    }

    inline uint8_t affine(uint8_t b) {
        return (uint8_t)(b
                       ^ rotl8(b, 1)
                       ^ rotl8(b, 2)
                       ^ rotl8(b, 3)
                       ^ rotl8(b, 4)
                       ^ 0x63);
    }

    inline uint8_t sbox_eval(uint8_t b) {
        return affine(inverse(b));
    }

    void generateSbox(uint8_t sbox[256]) {
        for (int i = 0; i < 256; ++i) {
            sbox[i] = sbox_eval((uint8_t)i);
        }
    }
}

namespace AES128 {

    using GF256::xtime;
    using GF256::sbox_eval;

    inline uint8_t mul2(uint8_t b) { return xtime(b); }
    inline uint8_t mul3(uint8_t b) { return (uint8_t)(xtime(b) ^ b); }

    void AddRoundKey(uint8_t s[4][4], const uint8_t rk[16]) {
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j)
                s[i][j] ^= rk[4*i + j];
    }

    void SubBytes(uint8_t s[4][4]) {
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j)
                s[i][j] = sbox_eval(s[i][j]);
    }

    void ShiftRows(uint8_t s[4][4]) {
        uint8_t t;
        t = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2];
        s[1][2] = s[1][3]; s[1][3] = t;
        t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t;
        t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t;
        t = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1];
        s[3][1] = s[3][0]; s[3][0] = t;
    }

    void MixColumns(uint8_t s[4][4]) {
        for (int c = 0; c < 4; ++c) {
            uint8_t a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
            s[0][c] = (uint8_t)(mul2(a0) ^ mul3(a1) ^ a2 ^ a3);
            s[1][c] = (uint8_t)(a0 ^ mul2(a1) ^ mul3(a2) ^ a3);
            s[2][c] = (uint8_t)(a0 ^ a1 ^ mul2(a2) ^ mul3(a3));
            s[3][c] = (uint8_t)(mul3(a0) ^ a1 ^ a2 ^ mul2(a3));
        }
    }

    void KeyExpansion(const uint8_t key[16], uint8_t rk[11][16]) {
        static const uint8_t Rcon[11] = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
        };

        uint8_t w[44][4];
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j)
                w[i][j] = key[4*i + j];

        for (int i = 4; i < 44; ++i) {
            uint8_t temp[4];
            for (int j = 0; j < 4; ++j) temp[j] = w[i-1][j];

            if (i % 4 == 0) {
                uint8_t t0 = temp[0];
                temp[0] = temp[1]; temp[1] = temp[2];
                temp[2] = temp[3]; temp[3] = t0;
                for (int j = 0; j < 4; ++j)
                    temp[j] = sbox_eval(temp[j]);
                temp[0] ^= Rcon[i/4];
            }
            for (int j = 0; j < 4; ++j)
                w[i][j] = (uint8_t)(w[i-4][j] ^ temp[j]);
        }

        for (int r = 0; r < 11; ++r)
            for (int i = 0; i < 4; ++i)
                for (int j = 0; j < 4; ++j)
                    rk[r][4*i + j] = w[4*r + i][j];
    }

    void EncryptBlock(const uint8_t in[16], uint8_t out[16],
                      const uint8_t rk[11][16]) {
        uint8_t s[4][4];
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j)
                s[i][j] = in[4*i + j];

        AddRoundKey(s, rk[0]);

        for (int round = 1; round <= 9; ++round) {
            SubBytes(s);
            ShiftRows(s);
            MixColumns(s);
            AddRoundKey(s, rk[round]);
        }

        SubBytes(s);
        ShiftRows(s);
        AddRoundKey(s, rk[10]);

        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j)
                out[4*i + j] = s[i][j];
    }

    void Encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
        uint8_t rk[11][16];
        KeyExpansion(key, rk);
        EncryptBlock(in, out, rk);
    }
}

namespace GCM {

    struct Block128 {
        uint64_t hi;
        uint64_t lo;
    };

    inline Block128 load_be(const uint8_t b[16]) {
        Block128 r{0, 0};
        for (int i = 0; i < 8; ++i)  r.hi = (r.hi << 8) | b[i];
        for (int i = 8; i < 16; ++i) r.lo = (r.lo << 8) | b[i];
        return r;
    }

    inline void store_be(Block128 v, uint8_t b[16]) {
        for (int i = 7; i >= 0; --i) { b[i]     = (uint8_t)(v.hi & 0xFF); v.hi >>= 8; }
        for (int i = 15; i >= 8; --i){ b[i]     = (uint8_t)(v.lo & 0xFF); v.lo >>= 8; }
    }

    inline Block128 xor128(Block128 a, Block128 b) {
        return Block128{ a.hi ^ b.hi, a.lo ^ b.lo };
    }

    inline Block128 gf128_mul(Block128 X, Block128 H) {
        Block128 Z{0, 0};
        Block128 V = H;

        for (int i = 0; i < 128; ++i) {
            uint64_t bit;
            if (i < 64) bit = (X.hi >> (63 - i)) & 1ULL;
            else        bit = (X.lo >> (127 - i)) & 1ULL;

            uint64_t mask = (uint64_t)(-(int64_t)bit);
            Z.hi ^= V.hi & mask;
            Z.lo ^= V.lo & mask;

            uint64_t lsb = V.lo & 1ULL;
            V.lo = (V.lo >> 1) | (V.hi << 63);
            V.hi >>= 1;

            uint64_t rmask = (uint64_t)(-(int64_t)lsb);
            V.hi ^= 0xE100000000000000ULL & rmask;
        }
        return Z;
    }

    Block128 ghash(const uint8_t* aad, size_t aad_len,
                   const uint8_t* ct,  size_t ct_len,
                   Block128 H)
    {
        Block128 Y{0, 0};

        size_t off = 0;
        while (off + 16 <= aad_len) {
            Y = gf128_mul(xor128(Y, load_be(aad + off)), H);
            off += 16;
        }
        if (off < aad_len) {
            uint8_t buf[16] = {0};
            std::memcpy(buf, aad + off, aad_len - off);
            Y = gf128_mul(xor128(Y, load_be(buf)), H);
        }

        off = 0;
        while (off + 16 <= ct_len) {
            Y = gf128_mul(xor128(Y, load_be(ct + off)), H);
            off += 16;
        }
        if (off < ct_len) {
            uint8_t buf[16] = {0};
            std::memcpy(buf, ct + off, ct_len - off);
            Y = gf128_mul(xor128(Y, load_be(buf)), H);
        }

        uint8_t lenbuf[16];
        uint64_t aad_bits = (uint64_t)aad_len * 8ULL;
        uint64_t ct_bits  = (uint64_t)ct_len  * 8ULL;
        for (int i = 7; i >= 0; --i) { lenbuf[i]     = (uint8_t)(aad_bits & 0xFF); aad_bits >>= 8; }
        for (int i = 15; i >= 8; --i){ lenbuf[i]     = (uint8_t)(ct_bits  & 0xFF); ct_bits  >>= 8; }
        Y = gf128_mul(xor128(Y, load_be(lenbuf)), H);

        return Y;
    }

    void Encrypt(const uint8_t key[16],
                 const uint8_t iv[12],
                 const uint8_t* aad, size_t aad_len,
                 const uint8_t* pt,  size_t pt_len,
                 uint8_t* ct,
                 uint8_t out_tag[16])
    {
        uint8_t rk[11][16];
        AES128::KeyExpansion(key, rk);

        uint8_t zero[16] = {0};
        uint8_t Hbytes[16];
        AES128::EncryptBlock(zero, Hbytes, rk);
        Block128 H = load_be(Hbytes);

        uint8_t CB[16];
        std::memcpy(CB, iv, 12);
        CB[12] = 0; CB[13] = 0; CB[14] = 0; CB[15] = 1;

        uint8_t E0[16];
        AES128::EncryptBlock(CB, E0, rk);

        uint32_t counter = 2;
        size_t off = 0;
        while (off < pt_len) {
            uint8_t cb[16];
            std::memcpy(cb, iv, 12);
            cb[12] = (uint8_t)(counter >> 24);
            cb[13] = (uint8_t)(counter >> 16);
            cb[14] = (uint8_t)(counter >> 8);
            cb[15] = (uint8_t)(counter);

            uint8_t gamma[16];
            AES128::EncryptBlock(cb, gamma, rk);

            size_t chunk = (pt_len - off < 16) ? (pt_len - off) : 16;
            for (size_t i = 0; i < chunk; ++i)
                ct[off + i] = (uint8_t)(pt[off + i] ^ gamma[i]);

            ++counter;
            off += chunk;
        }

        Block128 S = ghash(aad, aad_len, ct, pt_len, H);

        Block128 E0b = load_be(E0);
        Block128 T   = xor128(S, E0b);
        store_be(T, out_tag);
    }

    bool verify_tag(const uint8_t T[16], const uint8_t Tp[16]) {
        uint8_t diff = 0;
        for (int i = 0; i < 16; ++i)
            diff |= (uint8_t)(T[i] ^ Tp[i]);
        return diff == 0;
    }
}

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    std::printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) std::printf("%02X", data[i]);
    std::printf("\n");
}

int main() {
    std::printf("=== Вариант 11: AES-128 с p(x)=0x14D ===\n\n");

    std::printf("--- Тест 1. GF(2^8), p(x)=0x14D ---\n");
    uint8_t a = 0x57, b = 0x83;
    std::printf("add(0x%02X, 0x%02X)      = 0x%02X\n",
                a, b, GF256::add(a, b));
    std::printf("multiply(0x%02X, 0x%02X) = 0x%02X\n",
                a, b, GF256::multiply(a, b));

    uint8_t inv_a = GF256::inverse(a);
    std::printf("inverse(0x%02X)          = 0x%02X\n", a, inv_a);
    std::printf("check: a * a^{-1}        = 0x%02X (ожидается 0x01)\n",
                GF256::multiply(a, inv_a));

    uint8_t inv_zero = GF256::inverse(0x00);
    std::printf("inverse(0x00)            = 0x%02X (ожидается 0x00)\n\n",
                inv_zero);

    std::printf("--- Тест 2. S-box (первые 32 значения, p(x)=0x14D) ---\n");
    uint8_t sbox[256];
    GF256::generateSbox(sbox);
    std::printf("S[00..0F] = ");
    for (int i = 0; i < 16; ++i) std::printf("%02X ", sbox[i]);
    std::printf("\n");
    std::printf("S[10..1F] = ");
    for (int i = 16; i < 32; ++i) std::printf("%02X ", sbox[i]);
    std::printf("\n\n");

    std::printf("--- Тест 3. AES-128 (p(x)=0x14D) ---\n");
    uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    uint8_t plain[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
    };
    uint8_t cipher[16];
    AES128::Encrypt(key, plain, cipher);
    print_hex("key       ", key,    16);
    print_hex("plaintext ", plain,  16);
    print_hex("ciphertext", cipher, 16);
    std::printf("\n");

    std::printf("--- Тест 4. GCM AEAD ---\n");
    uint8_t gcm_key[16] = {
        0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,
        0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08
    };
    uint8_t iv[12] = {
        0xCA,0xFE,0xBA,0xBE,0xFA,0xCE,0xDB,0xAD,
        0xDE,0xCA,0xF8,0x88
    };
    uint8_t aad[16] = {
        0xFE,0xED,0xFA,0xCE,0xDE,0xAD,0xBE,0xEF,
        0xFE,0xED,0xFA,0xCE,0xDE,0xAD,0xBE,0xEF
    };
    uint8_t pt[16] = {
        0xD9,0x31,0x32,0x25,0xF8,0x84,0x06,0xE5,
        0xA5,0x59,0x09,0xC5,0xAF,0xF5,0x26,0x9E
    };
    uint8_t ct[16] = {0};
    uint8_t tag[16] = {0};

    GCM::Encrypt(gcm_key, iv, aad, sizeof(aad), pt, sizeof(pt), ct, tag);

    print_hex("GCM key   ", gcm_key, 16);
    print_hex("GCM IV    ", iv,      12);
    print_hex("GCM AAD   ", aad,     16);
    print_hex("GCM plain ", pt,      16);
    print_hex("GCM cipher", ct,      16);
    print_hex("GCM tag   ", tag,     16);

    std::printf("\n--- Тест 5. Constant-time verify_tag ---\n");
    uint8_t tag_ok[16];
    std::memcpy(tag_ok, tag, 16);
    std::printf("verify(тег == эталон)     : %s\n",
                GCM::verify_tag(tag, tag_ok) ? "OK" : "FAIL");

    uint8_t tag_bad[16];
    std::memcpy(tag_bad, tag, 16);
    tag_bad[0] ^= 0x01;
    std::printf("verify(тег испорчен [0])  : %s\n",
                GCM::verify_tag(tag, tag_bad) ? "OK (плохо)" : "FAIL (ожидаемо)");

    uint8_t tag_bad2[16];
    std::memcpy(tag_bad2, tag, 16);
    tag_bad2[15] ^= 0x80;
    std::printf("verify(тег испорчен [15]) : %s\n",
                GCM::verify_tag(tag, tag_bad2) ? "OK (плохо)" : "FAIL (ожидаемо)");

    std::printf("\n--- Тест 6. S-box биекция (p(x)=0x14D) ---\n");
    bool seen[256] = {false};
    bool bij = true;
    for (int i = 0; i < 256; ++i) {
        if (seen[sbox[i]]) { bij = false; break; }
        seen[sbox[i]] = true;
    }
    std::printf("S-box является биекцией: %s\n", bij ? "ДА" : "НЕТ");

    std::printf("\n--- Тест 7. a * a^{-1} = 0x01 для всех a != 0 ---\n");
    bool all_ok = true;
    for (int i = 1; i < 256; ++i) {
        uint8_t ai = GF256::inverse((uint8_t)i);
        if (GF256::multiply((uint8_t)i, ai) != 0x01) {
            all_ok = false;
            std::printf("  FAIL при a=0x%02X: a*inv=0x%02X\n",
                        i, GF256::multiply((uint8_t)i, ai));
        }
    }
    std::printf("Все 255 ненулевых элементов обратимы: %s\n",
                all_ok ? "ДА" : "НЕТ");

    return 0;
}
