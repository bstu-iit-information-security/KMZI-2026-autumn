#include <cstdint>
#include <cstdio>
#include <cstring>

#include "belt.hpp"
#include "gcm.hpp"
#include "gf256.hpp"

static const uint16_t P_X = 0x1C3;

static int failed = 0;

static void check(const char* name, bool ok) {
    std::printf("[%s] %s\n", ok ? "OK  " : "FAIL", name);
    if (!ok) {
        ++failed;
    }
}

static void printHex(const char* label, const uint8_t* d, size_t n) {
    std::printf("%s", label);
    for (size_t i = 0; i < n; ++i) {
        std::printf("%02X", d[i]);
    }
    std::printf("\n");
}

static void testGaloisField() {
    check("0x57 * 0x83 mod 0x11B == 0xC1", GaloisField::multiply(0x57, 0x83, 0x11B) == 0xC1);
    check("add(0x57, 0x83) == 0xD4", GaloisField::add(0x57, 0x83) == 0xD4);
    check("inverse(0x00) == 0x00", GaloisField::inverse(0x00, P_X) == 0x00);
    check("0x80 * 0x02 mod 0x1C3 == 0xC3 (overflow)", GaloisField::multiply(0x80, 0x02, P_X) == 0xC3);
    check("0xFF * 0xFF mod 0x1C3 matches slow reference", [] {
        uint16_t acc = 0;
        uint16_t a = 0xFF;
        for (int i = 0; i < 8; ++i) {
            if ((0xFF >> i) & 1) {
                acc ^= static_cast<uint16_t>(a << i);
            }
        }
        for (int bit = 14; bit >= 8; --bit) {
            if ((acc >> bit) & 1) {
                acc ^= static_cast<uint16_t>(P_X << (bit - 8));
            }
        }
        return GaloisField::multiply(0xFF, 0xFF, P_X) == static_cast<uint8_t>(acc);
    }());

    bool allInverse = true;
    for (int a = 1; a < 256; ++a) {
        uint8_t inv = GaloisField::inverse(static_cast<uint8_t>(a), P_X);
        if (GaloisField::multiply(static_cast<uint8_t>(a), inv, P_X) != 1) {
            allInverse = false;
        }
    }
    check("a * inverse(a) == 1 for all a != 0 in GF(2^8) mod 0x1C3", allInverse);

    auto aes = GaloisField::buildSBox(0x11B);
    check("S-box for 0x11B: S[0x00]=0x63 S[0x01]=0x7C S[0x53]=0xED", aes[0x00] == 0x63 && aes[0x01] == 0x7C && aes[0x53] == 0xED);

    auto mine = GaloisField::buildSBox(P_X);
    bool perm = true;
    bool seen[256] = {false};
    for (int i = 0; i < 256; ++i) {
        if (seen[mine[i]]) {
            perm = false;
        }
        seen[mine[i]] = true;
    }
    check("S-box for 0x1C3 is a permutation of 0..255", perm);
    std::printf("S-box(0x1C3) first row: ");
    for (int i = 0; i < 16; ++i) {
        std::printf("%02X ", mine[i]);
    }
    std::printf("\n");
}

static void testBelt() {
    const uint8_t key[32] = {
        0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6, 0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
        0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6};
    const uint8_t x[16] = {0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4};
    const uint8_t expected[16] = {0x69, 0xCC, 0xA1, 0xC9, 0x35, 0x57, 0xC9, 0xE3, 0xD6, 0x6B, 0xC3, 0xE0, 0xFA, 0x88, 0xFA, 0x6E};
    Belt belt(key);
    uint8_t y[16];
    belt.encryptBlock(x, y);
    printHex("belt-block Y = ", y, 16);
    check("belt-block test vector (STB 34.101.31, A.1)", std::memcmp(y, expected, 16) == 0);
}

static void testGcm() {
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) {
        key[i] = static_cast<uint8_t>(i * 7 + 1);
    }
    uint8_t iv[12];
    for (int i = 0; i < 12; ++i) {
        iv[i] = static_cast<uint8_t>(0xA0 + i);
    }
    const uint8_t aad[20] = {'h', 'e', 'a', 'd', 'e', 'r', '-', 'd', 'a', 't', 'a', '-', '0', '1', '2', '3', '4', '5', '6', '7'};
    const uint8_t plain[37] = {'s', 'e', 'c', 'r', 'e', 't', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e', ' ',
                               'f', 'o', 'r', ' ', 't', 'h', 'e', ' ', 'l', 'a', 'b', ' ', 'n', 'u', 'm', 'b', 'e', 'r', ' ', 'o', 'n', 'e'};

    Belt belt(key);
    Gcm<Belt> gcm(belt);

    uint8_t ct[37];
    uint8_t tag[16];
    gcm.encrypt(iv, aad, sizeof(aad), plain, sizeof(plain), ct, tag);
    printHex("ciphertext = ", ct, sizeof(ct));
    printHex("tag        = ", tag, 16);

    uint8_t back[37];
    bool ok = gcm.decrypt(iv, aad, sizeof(aad), ct, sizeof(ct), tag, back);
    check("decrypt returns true on valid data", ok);
    check("decrypted text equals original", std::memcmp(back, plain, sizeof(plain)) == 0);

    uint8_t badTag[16];
    std::memcpy(badTag, tag, 16);
    badTag[15] ^= 0x01;
    check("flip last tag byte -> rejected", !gcm.decrypt(iv, aad, sizeof(aad), ct, sizeof(ct), badTag, back));

    std::memcpy(badTag, tag, 16);
    badTag[0] ^= 0x80;
    check("flip first tag byte -> rejected", !gcm.decrypt(iv, aad, sizeof(aad), ct, sizeof(ct), badTag, back));

    uint8_t badCt[37];
    std::memcpy(badCt, ct, sizeof(ct));
    badCt[5] ^= 0x01;
    check("flip ciphertext bit -> rejected", !gcm.decrypt(iv, aad, sizeof(aad), badCt, sizeof(badCt), tag, back));

    uint8_t badAad[20];
    std::memcpy(badAad, aad, sizeof(aad));
    badAad[3] ^= 0x01;
    check("flip AAD bit -> rejected", !gcm.decrypt(iv, badAad, sizeof(badAad), ct, sizeof(ct), tag, back));

    uint8_t ct0[1];
    uint8_t tag0[16];
    gcm.encrypt(iv, nullptr, 0, nullptr, 0, ct0, tag0);
    check("empty message and empty AAD still give a tag that verifies", gcm.decrypt(iv, nullptr, 0, ct0, 0, tag0, back));
}

int main() {
    std::printf("=== Module 1: Galois field calculator ===\n");
    testGaloisField();
    std::printf("\n=== Module 2: Belt block cipher ===\n");
    testBelt();
    std::printf("\n=== Module 3: GCM + constant-time tag check ===\n");
    testGcm();
    std::printf("\n%s\n", failed == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return failed == 0 ? 0 : 1;
}
