#include <cstdint>
#include <cstring>
#include <cstdio>
#include <array>
#include <vector>
#include <windows.h>

namespace Galois {

inline uint8_t add(uint8_t a, uint8_t b) { return uint8_t(a ^ b); }

inline uint8_t xtime(uint8_t b, uint8_t p_byte) {
    uint8_t hi   = uint8_t(b >> 7);
    uint8_t mask = uint8_t(0u - uint32_t(hi));
    return uint8_t(uint8_t(b << 1) ^ (mask & p_byte));
}

uint8_t multiply(uint8_t a, uint8_t b, uint16_t p_x) {
    const uint8_t p_byte = uint8_t(p_x & 0xFFu);
    uint8_t result = 0;
    uint8_t x = a;
    for (int i = 0; i < 8; ++i) {
        uint8_t bit  = uint8_t((b >> i) & 1u);
        uint8_t mask = uint8_t(0u - uint32_t(bit));
        result ^= uint8_t(x & mask);
        x = xtime(x, p_byte);
    }
    return result;
}

inline uint8_t square(uint8_t a, uint16_t p_x) { return multiply(a, a, p_x); }

uint8_t inverse(uint8_t a, uint16_t p_x) {
    if (a == 0) return 0;
    uint8_t a2   = square(a,      p_x);
    uint8_t a4   = square(a2,     p_x);
    uint8_t a8   = square(a4,     p_x);
    uint8_t a16  = square(a8,     p_x);
    uint8_t a32  = square(a16,    p_x);
    uint8_t a64  = square(a32,    p_x);
    uint8_t a128 = square(a64,    p_x);
    uint8_t r = a128;
    r = multiply(r, a64,  p_x);
    r = multiply(r, a32,  p_x);
    r = multiply(r, a16,  p_x);
    r = multiply(r, a8,   p_x);
    r = multiply(r, a4,   p_x);
    r = multiply(r, a2,   p_x);
    return r;
}

inline uint8_t affine(uint8_t x) {
    uint8_t y = 0;
    for (int i = 0; i < 8; ++i) {
        uint8_t b_i  = uint8_t((x >> i) & 1u);
        uint8_t b_i4 = uint8_t((x >> ((i + 4) & 7)) & 1u);
        uint8_t b_i5 = uint8_t((x >> ((i + 5) & 7)) & 1u);
        uint8_t b_i6 = uint8_t((x >> ((i + 6) & 7)) & 1u);
        uint8_t b_i7 = uint8_t((x >> ((i + 7) & 7)) & 1u);
        uint8_t v = uint8_t(b_i ^ b_i4 ^ b_i5 ^ b_i6 ^ b_i7);
        y |= uint8_t(v << i);
    }
    return uint8_t(y ^ 0x63u);
}

std::array<uint8_t, 256> generateSbox(uint16_t p_x) {
    std::array<uint8_t, 256> S{};
    for (int i = 0; i < 256; ++i) {
        uint8_t inv = inverse(uint8_t(i), p_x);
        S[size_t(i)] = affine(inv);
    }
    return S;
}

}

namespace Belt {

inline uint8_t H(uint8_t b) {
    uint8_t inv = Galois::inverse(b, 0x11B);
    return Galois::affine(inv);
}

inline uint32_t rotl32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

uint32_t G(uint32_t u, int r) {
    uint32_t v = 0;
    v |= uint32_t(H(uint8_t(u        & 0xFFu))) << 0;
    v |= uint32_t(H(uint8_t((u >> 8)  & 0xFFu))) << 8;
    v |= uint32_t(H(uint8_t((u >> 16) & 0xFFu))) << 16;
    v |= uint32_t(H(uint8_t((u >> 24) & 0xFFu))) << 24;
    return rotl32(v, r);
}

class Cipher {
public:
    uint32_t K[8];
    uint32_t rk[56];

    void setKey(const uint8_t key[32]) {
        for (int i = 0; i < 8; ++i) {
            K[i] = uint32_t(key[4*i    ])        |
                   uint32_t(key[4*i + 1]) << 8   |
                   uint32_t(key[4*i + 2]) << 16  |
                   uint32_t(key[4*i + 3]) << 24;
        }
        for (int i = 1; i <= 56; ++i) {
            rk[i] = K[(i - 1) % 8];
        }
    }

    void encryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        uint32_t a = load32(in + 0);
        uint32_t b = load32(in + 4);
        uint32_t c = load32(in + 8);
        uint32_t d = load32(in + 12);

        for (int i = 1; i <= 8; ++i) {
            const int base = 7 * i - 6;
            b ^= G(a + rk[base + 0], 5);
            c ^= G(d + rk[base + 1], 21);
            a -= G(b + rk[base + 2], 13);
            uint32_t e = G(b + c + rk[base + 3], 21) ^ uint32_t(i);
            b += e;
            c -= e;
            d += G(c + rk[base + 4], 13);
            b ^= G(a + rk[base + 5], 21);
            c ^= G(d + rk[base + 6], 5);
            uint32_t t;
            t = a; a = b; b = t;
            t = c; c = d; d = t;
            t = b; b = c; c = t;
        }
        store32(out + 0,  b);
        store32(out + 4,  d);
        store32(out + 8,  a);
        store32(out + 12, c);
    }

private:
    static uint32_t load32(const uint8_t* p) {
        return uint32_t(p[0]) | uint32_t(p[1]) << 8 |
               uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
    }
    static void store32(uint8_t* p, uint32_t v) {
        p[0] = uint8_t(v);       p[1] = uint8_t(v >> 8);
        p[2] = uint8_t(v >> 16); p[3] = uint8_t(v >> 24);
    }
};

}

namespace GHashField {

struct U128 {
    uint64_t hi, lo;
};

inline U128 xr(U128 a, U128 b) { return {a.hi ^ b.hi, a.lo ^ b.lo}; }

inline U128 shr1(U128 x) {
    uint64_t lo_lsb = x.lo & 1u;
    uint64_t mask   = 0u - lo_lsb;
    U128 r;
    r.hi = (x.hi >> 1) ^ (mask & 0xE100000000000000ull);
    r.lo = (x.lo >> 1) | (x.hi << 63);
    return r;
}

U128 mul(U128 a, U128 b) {
    U128 z{0, 0};
    U128 v = a;
    for (int i = 0; i < 128; ++i) {
        uint64_t bit;
        if (i < 64) bit = (b.lo >> i) & 1u;
        else        bit = (b.hi >> (i - 64)) & 1u;
        uint64_t mask = 0u - bit;
        z.hi ^= v.hi & mask;
        z.lo ^= v.lo & mask;
        v = shr1(v);
    }
    return z;
}

}

class GCM {
public:
    Belt::Cipher cipher;
    GHashField::U128 Hkey;

    void setKey(const uint8_t key[32]) {
        cipher.setKey(key);
        uint8_t zero[16] = {0};
        uint8_t h[16];
        cipher.encryptBlock(zero, h);
        Hkey.hi = load64be(h + 0);
        Hkey.lo = load64be(h + 8);
    }

    void encrypt(const uint8_t* iv, size_t iv_len,
                 const uint8_t* aad, size_t aad_len,
                 const uint8_t* pt,  size_t pt_len,
                 std::vector<uint8_t>& ct,
                 uint8_t tag[16]) const
    {
        ct.resize(pt_len);

        uint8_t J0[16] = {0};
        if (iv_len == 12) {
            std::memcpy(J0, iv, 12);
            J0[15] = 1;
        } else {
            std::memcpy(J0, iv, iv_len < 16 ? iv_len : 16);
            J0[15] = 1;
        }

        uint8_t ctr[16];
        std::memcpy(ctr, J0, 16);
        uint32_t c32 = 2;
        uint8_t gamma[16];
        size_t off = 0;
        while (off < pt_len) {
            ctr[12] = uint8_t(c32 >> 24);
            ctr[13] = uint8_t(c32 >> 16);
            ctr[14] = uint8_t(c32 >> 8);
            ctr[15] = uint8_t(c32);
            cipher.encryptBlock(ctr, gamma);
            size_t n = (pt_len - off < 16) ? (pt_len - off) : 16;
            for (size_t i = 0; i < n; ++i)
                ct[off + i] = uint8_t(pt[off + i] ^ gamma[i]);
            ++c32;
            off += n;
        }

        GHashField::U128 y{0, 0};
        auto ghashBlock = [&](const uint8_t blk[16]) {
            GHashField::U128 x;
            x.hi = load64be(blk + 0);
            x.lo = load64be(blk + 8);
            y = GHashField::mul(GHashField::xr(y, x), Hkey);
        };

        {
            uint8_t blk[16] = {0};
            size_t i = 0;
            while (i < aad_len) {
                size_t n = (aad_len - i < 16) ? (aad_len - i) : 16;
                std::memset(blk, 0, 16);
                std::memcpy(blk, aad + i, n);
                ghashBlock(blk);
                i += n;
            }
        }
        {
            uint8_t blk[16] = {0};
            size_t i = 0;
            while (i < pt_len) {
                size_t n = (pt_len - i < 16) ? (pt_len - i) : 16;
                std::memset(blk, 0, 16);
                std::memcpy(blk, ct.data() + i, n);
                ghashBlock(blk);
                i += n;
            }
        }
        {
            uint8_t lenblk[16];
            uint64_t aadBits = uint64_t(aad_len) * 8u;
            uint64_t cBits   = uint64_t(pt_len)  * 8u;
            store64be(lenblk + 0, aadBits);
            store64be(lenblk + 8, cBits);
            ghashBlock(lenblk);
        }

        uint8_t ek0[16];
        cipher.encryptBlock(J0, ek0);
        uint8_t ghashBytes[16];
        store64be(ghashBytes + 0, y.hi);
        store64be(ghashBytes + 8, y.lo);
        for (int i = 0; i < 16; ++i)
            tag[i] = uint8_t(ghashBytes[i] ^ ek0[i]);
    }

    static bool verifyTag(const uint8_t calc[16], const uint8_t recv[16]) {
        uint8_t acc = 0;
        for (int i = 0; i < 16; ++i)
            acc = uint8_t(acc | (calc[i] ^ recv[i]));
        return acc == 0;
    }

private:
    static uint64_t load64be(const uint8_t* p) {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
        return v;
    }
    static void store64be(uint8_t* p, uint64_t v) {
        for (int i = 7; i >= 0; --i) { p[i] = uint8_t(v & 0xFF); v >>= 8; }
    }
};

static void hexDump(const char* label, const uint8_t* d, size_t n) {
    std::printf("%s: ", label);
    for (size_t i = 0; i < n; ++i) std::printf("%02X", d[i]);
    std::printf("\n");
}

int main() {
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);

    std::printf("=== Galois GF(2^8), p(x)=0x11B ===\n");
    uint8_t inv = Galois::inverse(0x53, 0x11B);
    std::printf("inverse(0x53) = 0x%02X  (ожидается 0xCA)\n", inv);
    uint8_t prod = Galois::multiply(0x53, inv, 0x11B);
    std::printf("0x53 * inverse(0x53) = 0x%02X (ожидается 0x01)\n", prod);
    std::printf("inverse(0x00) = 0x%02X (ожидается 0x00)\n",
                Galois::inverse(0x00, 0x11B));
    auto S = Galois::generateSbox(0x11B);
    std::printf("S-box[0x00] = 0x%02X, S-box[0x53] = 0x%02X (AES: 0x63, 0xED)\n",
                S[0x00], S[0x53]);

    std::printf("\n=== БелТ (СТБ 34.101.31) ===\n");
    Belt::Cipher bc;
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = uint8_t(i);
    bc.setKey(key);

    uint8_t pt[16];
    for (int i = 0; i < 16; ++i) pt[i] = uint8_t(0x10 + i);
    uint8_t ct[16];
    bc.encryptBlock(pt, ct);
    hexDump("key",        key, 32);
    hexDump("plaintext",  pt,  16);
    hexDump("ciphertext", ct,  16);

    std::printf("\n=== AEAD GCM (поверх БелТ) ===\n");
    GCM gcm;
    gcm.setKey(key);

    uint8_t iv[12] = {0};
    const char* aadStr = "This is awesome aad";
    const char* msgStr = "Here is an awesome message :)";
    std::vector<uint8_t> out;
    uint8_t tag[16];
    gcm.encrypt(iv, 12,
                reinterpret_cast<const uint8_t*>(aadStr), std::strlen(aadStr),
                reinterpret_cast<const uint8_t*>(msgStr), std::strlen(msgStr),
                out, tag);
    hexDump("AAD",        reinterpret_cast<const uint8_t*>(aadStr), std::strlen(aadStr));
    hexDump("ciphertext", out.data(), out.size());
    hexDump("tag",        tag, 16);

    bool ok1 = GCM::verifyTag(tag, tag);
    uint8_t badTag[16]; std::memcpy(badTag, tag, 16);
    badTag[7] ^= 0x01;
    bool ok2 = GCM::verifyTag(tag, badTag);
    std::printf("verify(correct) = %s, verify(tampered) = %s\n",
                ok1 ? "true" : "false", ok2 ? "true" : "false");

    std::printf("\n=== Constant-time проверки ===\n");
    std::printf("xtime(0x57) = 0x%02X, xtime(0x80) = 0x%02X\n",
                Galois::xtime(0x57, 0x1B), Galois::xtime(0x80, 0x1B));
    std::printf("H(0x00) = 0x%02X, H(0x53) = 0x%02X\n",
                Belt::H(0x00), Belt::H(0x53));

    return 0;
}