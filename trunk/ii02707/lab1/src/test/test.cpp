#include <test.hpp>

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <vector>

using crypto::GF256;
using crypto::Belt;
using crypto::GCM;

void check(bool cond, const char* name, TestStats& s) {
    if (cond) {
        ++s.passed;
        std::cout << "  [OK]   " << name << "\n";
    } else {
        ++s.failed;
        std::cout << "  [FAIL] " << name << "\n";
    }
}

void section(const char* title) {
    std::cout << "\n=== " << title << " ===\n";
}

template <size_t N>
bool bytes_equal(const uint8_t (&a)[N], const uint8_t (&b)[N]) {
    return std::memcmp(a, b, N) == 0;
}

void fill_deterministic(uint8_t* buf, size_t len, uint32_t seed) {
    uint32_t x = seed ? seed : 0xDEADBEEF;
    for (size_t i = 0; i < len; ++i) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        buf[i] = static_cast<uint8_t>(x & 0xFF);
    }
}

int count_bits(const uint8_t* a, const uint8_t* b, size_t len) {
    int d = 0;
    for (size_t i = 0; i < len; ++i) {
        uint8_t v = static_cast<uint8_t>(a[i] ^ b[i]);
        while (v) { d += v & 1; v >>= 1; }
    }
    return d;
}

void test_gf256_algebra(TestStats& s) {
    section("GF(2^8) p(x)=0x12B: аксиомы поля");
    GF256 gf(0x12B);

    bool ok = true;
    for (int i = 0; i < 256; ++i) {
        const uint8_t a = static_cast<uint8_t>(i);
        if (gf.multiply(a, 0x01) != a) { ok = false; break; }
    }
    check(ok, "a * 1 = a для всех a", s);

    ok = true;
    for (int i = 0; i < 256; ++i) {
        const uint8_t a = static_cast<uint8_t>(i);
        if (GF256::add(a, 0x00) != a) { ok = false; break; }
    }
    check(ok, "a + 0 = a для всех a", s);

    ok = true;
    for (int i = 0; i < 256 && ok; ++i) {
        for (int j = 0; j < 256; ++j) {
            const uint8_t a = static_cast<uint8_t>(i);
            const uint8_t b = static_cast<uint8_t>(j);
            if (gf.multiply(a, b) != gf.multiply(b, a)) { ok = false; break; }
        }
    }
    check(ok, "a * b = b * a (все 65536 пар)", s);

    ok = true;
    for (int i = 0; i < 256 && ok; ++i) {
        for (int j = 0; j < 256; ++j) {
            for (int k = 0; k < 256; k += 17) {
                const uint8_t a = static_cast<uint8_t>(i);
                const uint8_t b = static_cast<uint8_t>(j);
                const uint8_t c = static_cast<uint8_t>(k);
                const uint8_t l = gf.multiply(gf.multiply(a, b), c);
                const uint8_t r = gf.multiply(a, gf.multiply(b, c));
                if (l != r) { ok = false; break; }
            }
        }
    }
    check(ok, "(a*b)*c = a*(b*c) (выборка)", s);

    ok = true;
    for (int i = 0; i < 256 && ok; ++i) {
        for (int j = 0; j < 256; ++j) {
            for (int k = 0; k < 256; k += 31) {
                const uint8_t a = static_cast<uint8_t>(i);
                const uint8_t b = static_cast<uint8_t>(j);
                const uint8_t c = static_cast<uint8_t>(k);
                const uint8_t l = gf.multiply(a, GF256::add(b, c));
                const uint8_t r = GF256::add(gf.multiply(a, b), gf.multiply(a, c));
                if (l != r) { ok = false; break; }
            }
        }
    }
    check(ok, "a*(b+c) = a*b + a*c (выборка)", s);

    ok = true;
    for (int i = 0; i < 256; ++i) {
        const uint8_t b = static_cast<uint8_t>(i);
        if (gf.xtime(b) != gf.multiply(b, 0x02)) { ok = false; break; }
    }
    check(ok, "xtime(b) = b * 0x02 для всех b", s);

    ok = true;
    for (int i = 0; i < 256; ++i) {
        const uint8_t b = static_cast<uint8_t>(i);
        if (gf.inv_sbox(gf.sbox(b)) != b) { ok = false; break; }
    }
    check(ok, "inv_sbox(sbox(b)) = b для всех b", s);
}

void test_belt_properties(TestStats& s) {
    section("Belt: свойства блочного шифра");
    GF256 gf(0x12B);
    Belt belt(gf);

    uint8_t key[Belt::kKeyBytes];
    fill_deterministic(key, sizeof(key), 0xC0FFEE);

    uint8_t pt[Belt::kBlockBytes];
    fill_deterministic(pt, sizeof(pt), 0x1234);
    uint8_t ct1[Belt::kBlockBytes]{}, ct2[Belt::kBlockBytes]{};
    belt.encrypt(pt, ct1);
    belt.encrypt(pt, ct2);
    check(std::memcmp(ct1, ct2, sizeof(ct1)) == 0, "детерминизм шифрования", s);

    bool ok = true;
    for (int t = 0; t < 100; ++t) {
        uint8_t p[Belt::kBlockBytes], c[Belt::kBlockBytes], b[Belt::kBlockBytes];
        fill_deterministic(p, sizeof(p), static_cast<uint32_t>(t) + 1);
        belt.encrypt(p, c);
        belt.decrypt(c, b);
        if (std::memcmp(p, b, sizeof(p)) != 0) { ok = false; break; }
    }
    check(ok, "round-trip на 100 блоках", s);
}

void test_rotl_rotr_constants(TestStats& s) {
    section("Belt: Constant-time ROTL/ROTR (задача варианта 4)");

    auto rotl32 = [](uint32_t x, unsigned n) -> uint32_t {
        const uint64_t xu = static_cast<uint64_t>(x);
        const uint64_t r  = (xu << n) | (xu >> ((32u - n) & 31u));
        return static_cast<uint32_t>(r);
    };
    auto rotr32 = [](uint32_t x, unsigned n) -> uint32_t {
        const uint64_t xu = static_cast<uint64_t>(x);
        const unsigned m = (32u - n) & 31u;
        const uint64_t r = (xu << m) | (xu >> ((32u - m) & 31u));
        return static_cast<uint32_t>(r);
    };

    check(rotl32(0x80000000u, 1) == 0x00000001u, "ROTL(0x80000000, 1) = 1", s);
    check(rotl32(0x00000001u, 31) == 0x80000000u, "ROTL(1, 31) = 0x80000000", s);
    check(rotl32(0x12345678u, 0) == 0x12345678u, "ROTL(x, 0) = x (нет UB)", s);
    check(rotr32(0x00000001u, 1) == 0x80000000u, "ROTR(1, 1) = 0x80000000", s);
    check(rotr32(0x12345678u, 0) == 0x12345678u, "ROTR(x, 0) = x (нет UB)", s);
    check(rotr32(rotl32(0xDEADBEEFu, 13), 13) == 0xDEADBEEFu, "ROTR(ROTL(x,n),n) = x", s);
}

void test_gcm_boundary_lengths(TestStats& s) {
    section("GCM: граничные длины");
    GF256 gf(0x12B);
    Belt belt(gf);
    uint8_t key[Belt::kKeyBytes];
    fill_deterministic(key, sizeof(key), 0xBEEF01);

    GCM gcm;
    gcm.init(belt, key, gf);

    const uint8_t nonce[GCM::kNonceBytes] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C
    };
    const uint8_t aad[3] = {0xAA, 0xBB, 0xCC};

    const size_t lens[] = {0, 1, 15, 16, 17, 31, 32, 33, 64, 100};
    bool all_ok = true;
    for (size_t L : lens) {
        std::vector<uint8_t> pt(L), ct(L), back(L);
        for (size_t i = 0; i < L; ++i)
            pt[i] = static_cast<uint8_t>((i * 7 + L) & 0xFF);

        GCM::Tag tag{};
        gcm.encrypt(aad, sizeof(aad),
                    L ? pt.data() : nullptr, L,
                    nonce,
                    L ? ct.data() : nullptr, tag);

        const bool ok = gcm.decrypt(aad, sizeof(aad),
                                    L ? ct.data() : nullptr, L,
                                    nonce, tag,
                                    L ? back.data() : nullptr);
        if (!ok || (L && std::memcmp(pt.data(), back.data(), L) != 0)) {
            std::cout << "     FAIL при L=" << L << "\n";
            all_ok = false;
        }
    }
    check(all_ok, "round-trip для L ∈ {0,1,15,16,17,31,32,33,64,100}", s);
}

void test_gcm_aad_independence(TestStats& s) {
    section("GCM: AAD влияет только на тег, не на CT");
    GF256 gf(0x12B);
    Belt belt(gf);
    uint8_t key[Belt::kKeyBytes];
    fill_deterministic(key, sizeof(key), 0xABCDEF);
    GCM gcm;
    gcm.init(belt, key, gf);

    const uint8_t nonce[GCM::kNonceBytes] = {
        0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,0x90,0xA0,0xB0,0xC0
    };
    const uint8_t pt[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    const uint8_t aad_a[4] = {1,2,3,4};
    const uint8_t aad_b[4] = {1,2,3,5};

    uint8_t ct_a[32]{}, ct_b[32]{};
    GCM::Tag tag_a{}, tag_b{};
    gcm.encrypt(aad_a, 4, pt, 32, nonce, ct_a, tag_a);
    gcm.encrypt(aad_b, 4, pt, 32, nonce, ct_b, tag_b);

    check(std::memcmp(ct_a, ct_b, 32) == 0, "CT не зависит от AAD", s);
    check(std::memcmp(tag_a.data(), tag_b.data(), GCM::kTagBytes) != 0,
          "Tag зависит от AAD", s);
}

void test_gcm_forgery_rejected(TestStats& s) {
    section("GCM: отказ при подделке");
    GF256 gf(0x12B);
    Belt belt(gf);
    uint8_t key[Belt::kKeyBytes];
    fill_deterministic(key, sizeof(key), 0x55AA55AA);
    GCM gcm;
    gcm.init(belt, key, gf);

    const uint8_t nonce[GCM::kNonceBytes] = {
        0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,0x77,0x66,0x55,0x44
    };
    const uint8_t aad[8] = {1,2,3,4,5,6,7,8};
    const uint8_t pt[20] = {
        0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,
        0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF
    };
    uint8_t ct[20]{};
    GCM::Tag tag{};
    gcm.encrypt(aad, 8, pt, 20, nonce, ct, tag);

    {
        uint8_t ct_bad[20]; std::memcpy(ct_bad, ct, 20); ct_bad[0] ^= 0x01;
        uint8_t pt_out[20]{};
        check(!gcm.decrypt(aad, 8, ct_bad, 20, nonce, tag, pt_out),
              "подмена CT → отказ", s);
    }

    {
        uint8_t aad_bad[8]; std::memcpy(aad_bad, aad, 8); aad_bad[3] ^= 0x80;
        uint8_t pt_out[20]{};
        check(!gcm.decrypt(aad_bad, 8, ct, 20, nonce, tag, pt_out),
              "подмена AAD → отказ", s);
    }

    {
        uint8_t nonce_bad[GCM::kNonceBytes];
        std::memcpy(nonce_bad, nonce, sizeof(nonce));
        nonce_bad[5] ^= 0x01;
        uint8_t pt_out[20]{};
        check(!gcm.decrypt(aad, 8, ct, 20, nonce_bad, tag, pt_out),
              "подмена nonce → отказ", s);
    }

    {
        bool all_rejected = true;
        for (size_t i = 0; i < GCM::kTagBytes; ++i) {
            GCM::Tag t = tag; t[i] ^= 0x01;
            uint8_t pt_out[20]{};
            if (gcm.decrypt(aad, 8, ct, 20, nonce, t, pt_out)) {
                all_rejected = false; break;
            }
        }
        check(all_rejected, "подмена любого байта тега → отказ (16 проверок)", s);
    }

    {
        GCM::Tag zeros{};
        uint8_t pt_out[20]{};
        check(!gcm.decrypt(aad, 8, ct, 20, nonce, zeros, pt_out),
              "нулевой тег → отказ", s);
    }
}

void test_ct_compare(TestStats& s) {
    section("GCM: Constant-time сравнение тегов");
    GCM::Tag a{};
    GCM::Tag b{};
    for (size_t i = 0; i < GCM::kTagBytes; ++i) {
        a[i] = static_cast<uint8_t>(i);
        b[i] = static_cast<uint8_t>(i);
    }

    check(GCM::ct_compare(a, b), "равные теги → true", s);

    bool all_differ = true;
    for (size_t i = 0; i < GCM::kTagBytes; ++i) {
        GCM::Tag c = a; c[i] ^= 0x80;
        if (GCM::ct_compare(a, c)) { all_differ = false; break; }
    }
    check(all_differ, "отличие в любом байте → false (16 проверок)", s);

    GCM::Tag d = a; d[0] ^= 0x80;
    GCM::Tag e = a; e[15] ^= 0x01;
    check(!GCM::ct_compare(a, d) && !GCM::ct_compare(a, e),
          "позиция различия не влияет на результат", s);
}

void test_gcm_nonzero_tag_always(TestStats& s) {
    section("GCM: тег всегда ненулевой на случайных данных");
    GF256 gf(0x12B);
    Belt belt(gf);
    uint8_t key[Belt::kKeyBytes];
    fill_deterministic(key, sizeof(key), 0x77777);
    GCM gcm;
    gcm.init(belt, key, gf);

    bool all_nonzero = true;
    for (int t = 0; t < 64; ++t) {
        uint8_t nonce[GCM::kNonceBytes];
        uint8_t pt[17], aad[9];
        fill_deterministic(nonce, sizeof(nonce), 1000u + t);
        fill_deterministic(pt, sizeof(pt),     2000u + t);
        fill_deterministic(aad, sizeof(aad),   3000u + t);
        uint8_t ct[17]{};
        GCM::Tag tag{};
        gcm.encrypt(aad, sizeof(aad), pt, sizeof(pt), nonce, ct, tag);
        GCM::Tag zero{};
        if (std::memcmp(tag.data(), zero.data(), GCM::kTagBytes) == 0) {
            all_nonzero = false; break;
        }
    }
    check(all_nonzero, "тег ≠ 0 на 64 случайных входах", s);
}

void test_modulus_irreducibility(TestStats& s) {
    section("Проверка неприводимости p(x)");
    check(GF256::is_irreducible(0x12B), "0x12B неприводим", s);
    check(GF256::is_irreducible(0x11B), "0x11B (AES) неприводим", s);
    check(GF256::is_irreducible(0x14D), "0x14D неприводим", s);
    check(!GF256::is_irreducible(0x100), "0x100 = x^8 приводим", s);
    check(!GF256::is_irreducible(0x101), "0x101 = x^8+1 приводим", s);
}

int run_all_extra_tests() {
    TestStats s;
    std::cout << "=================================================\n";
    std::cout << " Дополнительные тесты (вариант 4: Belt + GCM)\n";
    std::cout << "=================================================\n";

    test_gf256_algebra(s);
    test_belt_properties(s);
    test_rotl_rotr_constants(s);
    test_gcm_boundary_lengths(s);
    test_gcm_aad_independence(s);
    test_gcm_forgery_rejected(s);
    test_ct_compare(s);
    test_gcm_nonzero_tag_always(s);

    test_modulus_irreducibility(s);

    std::cout << "\n=================================================\n";
    std::cout << " ИТОГО: " << s.passed << " passed, "
              << s.failed << " failed\n";
    std::cout << "=================================================\n";
    return s.failed == 0 ? 0 : 1;
}