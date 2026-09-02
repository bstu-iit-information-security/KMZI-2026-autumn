#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <windows.h>

using namespace std;
using Byte = uint8_t;

struct GF256 {
    static Byte add(Byte a, Byte b) {
        return a ^ b;
    }

    static Byte mul(Byte a, Byte b, uint16_t p) {
        uint16_t r = 0;
        for (int i = 0; i < 8; ++i) {
            r ^= (uint16_t)a & (0u - (b & 1u));
            uint16_t c = (a >> 7) & 1u;
            a = (Byte)((a << 1) ^ ((p & 0xFF) & (0u - c)));
            b >>= 1;
        }
        return (Byte)r;
    }

    static Byte inv(Byte a, uint16_t p) {
        if (a == 0) return 0;

        Byte a2 = mul(a, a, p);
        Byte a4 = mul(a2, a2, p);
        Byte a8 = mul(a4, a4, p);
        Byte a16 = mul(a8, a8, p);
        Byte a32 = mul(a16, a16, p);
        Byte a64 = mul(a32, a32, p);
        Byte a128 = mul(a64, a64, p);

        Byte r = mul(a128, a64, p);
        r = mul(r, a32, p);
        r = mul(r, a16, p);
        r = mul(r, a8, p);
        r = mul(r, a4, p);
        return mul(r, a2, p);
    }
};

struct AES128 {
    Byte key[176];
    static constexpr uint16_t P = 0x171;

    static void mul_bits(const uint16_t a[8], const uint16_t b[8], uint16_t r[8]) {
        uint16_t t[15] = {};

        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 8; ++j)
                t[i + j] ^= a[i] & b[j];

        for (int i = 14; i >= 8; --i) {
            uint16_t m = t[i];
            t[i - 8] ^= m;
            t[i - 2] ^= m;
            t[i - 3] ^= m;
            t[i - 4] ^= m;
        }

        for (int i = 0; i < 8; ++i)
            r[i] = t[i];
    }

    static void inv_bits(const uint16_t in[8], uint16_t out[8]) {
        uint16_t a2[8], a4[8], a8[8], a16[8];
        uint16_t a32[8], a64[8], a128[8], t[8];

        mul_bits(in, in, a2);
        mul_bits(a2, a2, a4);
        mul_bits(a4, a4, a8);
        mul_bits(a8, a8, a16);
        mul_bits(a16, a16, a32);
        mul_bits(a32, a32, a64);
        mul_bits(a64, a64, a128);

        mul_bits(a128, a64, t);
        mul_bits(t, a32, t);
        mul_bits(t, a16, t);
        mul_bits(t, a8, t);
        mul_bits(t, a4, t);
        mul_bits(t, a2, out);
    }

    static void sub_bits(Byte s[16]) {
        uint16_t p[8] = {}, inv[8] = {}, out[8] = {};

        for (int i = 0; i < 16; ++i)
            for (int b = 0; b < 8; ++b)
                p[b] |= (uint16_t)(1u << i) &
                        (uint16_t)(0u - ((s[i] >> b) & 1u));

        inv_bits(p, inv);

        for (int i = 0; i < 8; ++i) {
            out[i] = inv[i] ^
                     inv[(i + 4) & 7] ^
                     inv[(i + 5) & 7] ^
                     inv[(i + 6) & 7] ^
                     inv[(i + 7) & 7] ^
                     (uint16_t)(0u - ((0x63 >> i) & 1u));
        }

        for (int i = 0; i < 16; ++i) {
            s[i] = 0;
            for (int b = 0; b < 8; ++b)
                s[i] |= (Byte)(((out[b] >> i) & 1u) << b);
        }
    }

    static Byte xtime(Byte x) {
        Byte m = (Byte)(0u - (x >> 7));
        return (Byte)((x << 1) ^ (0x71 & m));
    }

    void expand(const Byte k[16]) {
        memcpy(key, k, 16);
        Byte rc = 1;

        for (int r = 1; r <= 10; ++r) {
            Byte t[4];

            for (int i = 0; i < 4; ++i)
                t[i] = key[r * 16 - 4 + i];

            Byte tmp = t[0];
            t[0] = t[1];
            t[1] = t[2];
            t[2] = t[3];
            t[3] = tmp;

            Byte w[16] = {};
            for (int i = 0; i < 4; ++i)
                w[i] = t[i];

            sub_bits(w);

            for (int i = 0; i < 4; ++i)
                t[i] = w[i];

            t[0] ^= rc;

            int base = r * 16;

            for (int i = 0; i < 4; ++i)
                key[base + i] = key[base - 16 + i] ^ t[i];

            for (int j = 1; j < 4; ++j)
                for (int i = 0; i < 4; ++i)
                    key[base + j * 4 + i] =
                        key[base - 16 + j * 4 + i] ^
                        key[base + (j - 1) * 4 + i];

            rc = xtime(rc);
        }
    }

    void add_round(Byte s[16], int r) const {
        for (int i = 0; i < 16; ++i)
            s[i] ^= key[r * 16 + i];
    }

    void shift_rows(Byte s[16]) const {
        Byte t[16];

        for (int r = 0; r < 4; ++r)
            for (int c = 0; c < 4; ++c)
                t[r + 4 * c] = s[r + 4 * ((c + r) & 3)];

        memcpy(s, t, 16);
    }

    void mix_col(Byte s[16]) const {
        for (int c = 0; c < 4; ++c) {
            int i = c * 4;

            Byte a0 = s[i], a1 = s[i + 1];
            Byte a2 = s[i + 2], a3 = s[i + 3];

            Byte t0 = xtime(a0);
            Byte t1 = xtime(a1);
            Byte t2 = xtime(a2);
            Byte t3 = xtime(a3);

            s[i]     = t0 ^ t1 ^ a1 ^ a2 ^ a3;
            s[i + 1] = a0 ^ t1 ^ t2 ^ a2 ^ a3;
            s[i + 2] = a0 ^ a1 ^ t2 ^ t3 ^ a3;
            s[i + 3] = a0 ^ a1 ^ a2 ^ t3 ^ t0;
        }
    }

    void encrypt(const Byte in[16], Byte out[16]) const {
        Byte s[16];
        memcpy(s, in, 16);

        add_round(s, 0);

        for (int r = 1; r <= 9; ++r) {
            sub_bits(s);
            shift_rows(s);
            mix_col(s);
            add_round(s, r);
        }

        sub_bits(s);
        shift_rows(s);
        add_round(s, 10);

        memcpy(out, s, 16);
    }

    AES128(const Byte k[16]) {
        expand(k);
    }
};

struct GCM {
    AES128& aes;

    static __uint128_t load(const Byte d[16]) {
        __uint128_t x = 0;
        for (int i = 0; i < 16; ++i)
            x = (x << 8) | d[i];
        return x;
    }

    static void store(__uint128_t x, Byte d[16]) {
        for (int i = 15; i >= 0; --i) {
            d[i] = (Byte)x;
            x >>= 8;
        }
    }

    static __uint128_t mul128(__uint128_t x, __uint128_t y) {
        __uint128_t z = 0;

        for (int i = 0; i < 128; ++i) {
            z ^= y & (0u - ((x >> 127) & 1u));
            x <<= 1;

            uint64_t bit = (uint64_t)y & 1;
            y >>= 1;
            y ^= (__uint128_t)(0xE100000000000000ULL &
                               (0u - bit)) << 64;
        }

        return z;
    }

    static __uint128_t gh(
        __uint128_t h,
        const Byte* aad, int alen,
        const Byte* ct, int clen
    ) {
        __uint128_t y = 0;

        auto process = [&](const Byte* data, int len) {
            for (int i = 0; i < (len + 15) / 16; ++i) {
                Byte b[16] = {};
                int off = i * 16;
                int cnt = len - off;
                if (cnt > 16) cnt = 16;

                memcpy(b, data + off, cnt);
                y = mul128(y ^ load(b), h);
            }
        };

        process(aad, alen);
        process(ct, clen);

        Byte lb[16] = {};
        uint64_t abit = (uint64_t)alen * 8;
        uint64_t cbit = (uint64_t)clen * 8;

        for (int i = 0; i < 8; ++i) {
            lb[7 - i] = (Byte)(abit >> (8 * i));
            lb[15 - i] = (Byte)(cbit >> (8 * i));
        }

        return mul128(y ^ load(lb), h);
    }

    static void inc(Byte ctr[16]) {
        uint32_t v =
            ((uint32_t)ctr[12] << 24) |
            ((uint32_t)ctr[13] << 16) |
            ((uint32_t)ctr[14] << 8) |
            ctr[15];

        ++v;

        ctr[12] = (Byte)(v >> 24);
        ctr[13] = (Byte)(v >> 16);
        ctr[14] = (Byte)(v >> 8);
        ctr[15] = (Byte)v;
    }

    void tag(
        const Byte* ct, int clen,
        const Byte* aad, int alen,
        const Byte iv[12],
        Byte out[16]
    ) {
        Byte zero[16] = {};
        Byte hb[16];

        aes.encrypt(zero, hb);
        __uint128_t h = load(hb);

        __uint128_t s =
            gh(h, aad, alen, ct, clen);

        Byte j0[16] = {};
        memcpy(j0, iv, 12);
        j0[15] = 1;

        Byte e[16];
        aes.encrypt(j0, e);

        store(s ^ load(e), out);
    }

    void encrypt(
        const Byte* pt, int len,
        const Byte* aad, int alen,
        const Byte iv[12],
        Byte* ct, Byte out_tag[16]
    ) {
        Byte ctr[16] = {};
        memcpy(ctr, iv, 12);
        ctr[15] = 1;

        for (int b = 0; b < (len + 15) / 16; ++b) {
            inc(ctr);

            Byte stream[16];
            aes.encrypt(ctr, stream);

            int off = b * 16;
            int cnt = len - off;
            if (cnt > 16) cnt = 16;

            for (int i = 0; i < cnt; ++i)
                ct[off + i] = pt[off + i] ^ stream[i];
        }

        tag(ct, len, aad, alen, iv, out_tag);
    }

    bool verify(
        const Byte* ct, int len,
        const Byte* aad, int alen,
        const Byte iv[12],
        const Byte received[16]
    ) {
        Byte calculated[16];
        tag(ct, len, aad, alen, iv, calculated);

        volatile Byte diff = 0;

        for (int i = 0; i < 16; ++i)
            diff |= calculated[i] ^ received[i];

        return diff == 0;
    }

    GCM(AES128& a) : aes(a) {}
};

void printHex(const char* name, const Byte* data, int n) {
    cout << name << ": ";

    for (int i = 0; i < n; ++i)
        cout << hex << setw(2) << setfill('0')
             << (int)data[i] << ' ';

    cout << dec << '\n';
}

void testBitSlicing() {
    bool ok = true;

    for (int v = 0; v < 256; ++v) {
        Byte s[16];

        for (int i = 0; i < 16; ++i)
            s[i] = (Byte)v;

        Byte x = GF256::inv((Byte)v, AES128::P);
        Byte ref = 0;

        for (int i = 0; i < 8; ++i) {
            Byte bit =
                ((x >> i) & 1) ^
                ((x >> ((i + 4) & 7)) & 1) ^
                ((x >> ((i + 5) & 7)) & 1) ^
                ((x >> ((i + 6) & 7)) & 1) ^
                ((x >> ((i + 7) & 7)) & 1) ^
                ((0x63 >> i) & 1);

            ref |= (Byte)(bit << i);
        }

        AES128::sub_bits(s);

        for (int i = 0; i < 16; ++i)
            if (s[i] != ref)
                ok = false;
    }

    cout << "Òåñò áèòîâûõ ñðåçîâ: "
         << (ok ? "ÏÐÎÉÄÅÍ" : "ÍÅ ÏÐÎÉÄÅÍ") << '\n';
}

int main() {
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    setlocale(LC_ALL, "Russian");

    const uint16_t P = 0x171;

    Byte a = 0x57;
    Byte b = 0x83;

    cout << "GF(2^8), P = 0x171\n";

    Byte x = GF256::add(a, b);
    printHex("a XOR b", &x, 1);

    x = GF256::mul(a, b, P);
    printHex("a * b", &x, 1);

    x = GF256::inv(a, P);
    printHex("a^(-1)", &x, 1);

    x = GF256::mul(a, x, P);
    printHex("a * a^(-1)", &x, 1);

    cout << '\n';

    Byte key[16] = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,
        0x0C,0x0D,0x0E,0x0F
    };

    Byte pt[16] = {
        0x00,0x11,0x22,0x33,
        0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,
        0xCC,0xDD,0xEE,0xFF
    };

    AES128 aes(key);

    Byte enc[16];
    aes.encrypt(pt, enc);

    printHex("AES øèôðîòåêñò", enc, 16);

    testBitSlicing();

    cout << '\n';

    Byte iv[12] = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B
    };

    Byte aad[16] = {
        0xAA,0xBB,0xCC,0xDD,
        0xEE,0xFF,0x00,0x11,
        0x22,0x33,0x44,0x55,
        0x66,0x77,0x88,0x99
    };

    Byte ct[16], tag[16];

    GCM gcm(aes);

    gcm.encrypt(
        pt, 16,
        aad, 16,
        iv,
        ct, tag
    );

    printHex("GCM øèôðîòåêñò", ct, 16);
    printHex("GCM òåã", tag, 16);

    cout << "Ïðàâèëüíûé òåã: "
         << (gcm.verify(ct, 16, aad, 16, iv, tag)
             ? "ÂÅÐÍÛÉ" : "ÍÅÂÅÐÍÛÉ") << '\n';

    Byte badTag[16];
    memcpy(badTag, tag, 16);
    badTag[0] ^= 1;

    cout << "Èçìåí¸ííûé òåã: "
         << (gcm.verify(ct, 16, aad, 16, iv, badTag)
             ? "ÂÅÐÍÛÉ" : "ÍÅÂÅÐÍÛÉ") << '\n';

    Byte badCt[16];
    memcpy(badCt, ct, 16);
    badCt[0] ^= 1;

    cout << "Èçìåí¸ííûé øèôðîòåêñò: "
         << (gcm.verify(badCt, 16, aad, 16, iv, tag)
             ? "ÂÅÐÍÛÉ" : "ÍÅÂÅÐÍÛÉ") << '\n';

    Byte badAad[16];
    memcpy(badAad, aad, 16);
    badAad[0] ^= 1;

    cout << "Èçìåí¸ííûé AAD: "
         << (gcm.verify(ct, 16, badAad, 16, iv, tag)
             ? "ÂÅÐÍÛÉ" : "ÍÅÂÅÐÍÛÉ") << '\n';

    return 0;
}