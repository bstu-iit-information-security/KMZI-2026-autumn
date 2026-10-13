#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include "gf256.h"
#include "aes128.h"
#include "gcm.h"

using namespace lab1;

static void hexdump(const char* label, const uint8_t* data, size_t len) {
    std::printf("%-6s: ", label);
    for (size_t i = 0; i < len; ++i) std::printf("%02x", data[i]);
    std::printf("\n");
}

int main() {
    setlocale(LC_ALL, "RU");
    std::cout << "=== Лабораторная работа №1, вариант 5 ===\n";
    std::cout << "AES-128 + GCM\n";
    std::cout << "p(x) = x^8 + x^5 + x^3 + x^2 + 1 (0x12D)\n";
    std::cout << "f(x) = x^128 + x^7 + x^2 + x + 1\n";
    std::cout << "Constant-time: MixColumns без ветвлений\n\n";

    const uint16_t POLY = 0x12D;
    GaloisField gf(POLY);

    // ---------- 1. Калькулятор Галуа ----------
    std::cout << "--- 1. Galois Field Calculator ---\n";
    std::printf("poly = 0x%03X, poly_byte = 0x%02X\n", gf.poly(), gf.polyByte());

    uint8_t a = 0x57, b = 0x83;
    std::printf("add(0x%02x, 0x%02x)  = 0x%02x\n", a, b, GaloisField::add(a, b));
    std::printf("mul(0x%02x, 0x%02x)  = 0x%02x\n", a, b, gf.multiply(a, b));

    uint8_t inv = gf.inverse(a);
    std::printf("inv(0x%02x)          = 0x%02x (check mul = 0x%02x)\n",
        a, inv, gf.multiply(a, inv));
    std::printf("inv(0x00)            = 0x%02x (must be 0)\n", gf.inverse(0x00));

    // Проверка S-box на биекцию
    bool seen[256] = { false };
    bool bio = true;
    for (int i = 0; i < 256; ++i) {
        if (seen[gf.sbox()[i]]) { bio = false; break; }
        seen[gf.sbox()[i]] = true;
    }
    std::printf("S-box bijection: %s\n", bio ? "OK" : "FAIL");
    std::printf("S-box[0x00] = 0x%02x, S-box[0x01] = 0x%02x\n",
        gf.sbox()[0x00], gf.sbox()[0x01]);

    // ---------- 2. AES-128 ----------
    std::cout << "\n--- 2. AES-128 (custom p(x)=0x12D) ---\n";
    uint8_t key[16] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
    uint8_t pt[16] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                       0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
    uint8_t ct[16], dt[16];

    AES128 aes(key, gf);
    aes.encryptBlock(pt, ct);
    aes.decryptBlock(ct, dt);

    hexdump("key", key, 16);
    hexdump("pt ", pt, 16);
    hexdump("ct ", ct, 16);
    hexdump("dt ", dt, 16);
    std::printf("AES roundtrip: %s\n", std::memcmp(pt, dt, 16) == 0 ? "OK" : "FAIL");

    // ---------- 3. GCM ----------
    std::cout << "\n--- 3. GCM (AEAD) ---\n";
    uint8_t iv[12] = { 0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88 };
    const std::string aad_str = "Additional authenticated data";
    const std::string pt_str = "Hello, GCM! This is a test message for variant 5.";

    size_t aad_len = aad_str.size();
    size_t pt_len = pt_str.size();

    std::string ct_str(pt_len, '\0');
    std::string dec_str(pt_len, '\0');
    uint8_t tag[16];

    GCM gcm(key, POLY);
    gcm.encrypt(iv,
        reinterpret_cast<const uint8_t*>(aad_str.data()), aad_len,
        reinterpret_cast<const uint8_t*>(pt_str.data()), pt_len,
        reinterpret_cast<uint8_t*>(&ct_str[0]), tag);

    hexdump("IV ", iv, 12);
    hexdump("AAD", reinterpret_cast<const uint8_t*>(aad_str.data()), aad_len);
    hexdump("PT ", reinterpret_cast<const uint8_t*>(pt_str.data()), pt_len);
    hexdump("CT ", reinterpret_cast<const uint8_t*>(ct_str.data()), pt_len);
    hexdump("Tag", tag, 16);

    bool ok = gcm.decrypt(iv,
        reinterpret_cast<const uint8_t*>(aad_str.data()), aad_len,
        reinterpret_cast<const uint8_t*>(ct_str.data()), pt_len,
        reinterpret_cast<uint8_t*>(&dec_str[0]), tag);
    std::printf("GCM decrypt valid tag: %s\n", ok ? "OK" : "FAIL");
    std::printf("Decrypted: \"%s\"\n", dec_str.c_str());

    // Тест подмены тега
    uint8_t bad_tag[16];
    std::memcpy(bad_tag, tag, 16);
    bad_tag[0] ^= 0x01;
    bool ok2 = gcm.decrypt(iv,
        reinterpret_cast<const uint8_t*>(aad_str.data()), aad_len,
        reinterpret_cast<const uint8_t*>(ct_str.data()), pt_len,
        reinterpret_cast<uint8_t*>(&dec_str[0]), bad_tag);
    std::printf("GCM tampered tag:      %s\n", ok2 ? "FAIL(accepted)" : "OK(rejected)");

    // ---------- 4. Constant-time ----------
    std::cout << "\n--- 4. Constant-time tag compare ---\n";
    uint8_t t1[16] = { 0 }, t2[16] = { 0 };
    std::printf("equal zeros:        %s\n", constantTimeCompare(t1, t2, 16) ? "true" : "false");
    t2[15] = 1;
    std::printf("differ in last byte: %s\n", constantTimeCompare(t1, t2, 16) ? "true" : "false");
    t2[15] = 0; t2[0] = 1;
    std::printf("differ in first byte:%s\n", constantTimeCompare(t1, t2, 16) ? "true" : "false");

    return 0;
}