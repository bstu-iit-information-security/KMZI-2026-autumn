#include <cstdio>
#include <cstring>
#include "galois.h"
#include "aes128.h"
#include "gcm.h"

static void printHex(const char* label, const uint8_t* data, size_t len) {
    std::printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        std::printf("%02X", data[i]);
    }
    std::printf("\n");
}

int main() {
    GaloisField gf(0x14D);

    bool inverseOk = true;
    for (int a = 1; a < 256; ++a) {
        uint8_t inv = gf.inverse(static_cast<uint8_t>(a));
        uint8_t check = gf.multiply(static_cast<uint8_t>(a), inv);
        if (check != 0x01) {
            inverseOk = false;
        }
    }
    std::printf("Test 1 (inverse correctness for all nonzero elements): %s\n", inverseOk ? "PASS" : "FAIL");
    std::printf("Test 1b (inverse of 0x00 maps to 0x00):                %s\n", gf.inverse(0x00) == 0x00 ? "PASS" : "FAIL");

    bool karatsubaOk = true;
    for (int a = 0; a < 256; ++a) {
        for (int b = 0; b < 256; ++b) {
            if (gf.multiply(static_cast<uint8_t>(a), static_cast<uint8_t>(b)) !=
                gf.multiplyKaratsuba(static_cast<uint8_t>(a), static_cast<uint8_t>(b))) {
                karatsubaOk = false;
            }
        }
    }
    std::printf("Test 2 (Karatsuba multiplication matches shift-and-xor for all pairs): %s\n", karatsubaOk ? "PASS" : "FAIL");

    uint8_t sbox[256];
    uint8_t invSbox[256];
    gf.generateSBox(sbox, invSbox);
    bool sboxOk = true;
    for (int b = 0; b < 256; ++b) {
        if (invSbox[sbox[b]] != b) {
            sboxOk = false;
        }
    }
    std::printf("Test 3 (S-box is a bijection, inverse S-box correctness):              %s\n", sboxOk ? "PASS" : "FAIL");

    uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    AES128 aes(gf, key);

    uint8_t plainBlock[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    uint8_t cipherBlock[16];
    aes.encryptBlock(plainBlock, cipherBlock);
    printHex("Test 4 plaintext block ", plainBlock, 16);
    printHex("Test 4 ciphertext block", cipherBlock, 16);

    GCM gcm(aes);

    uint8_t iv[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    const char* aadText = "header-data";
    const char* msgText = "Laboratory work variant 11: AES-128 with custom GF(2^8) polynomial and Karatsuba multiplication.";
    size_t aadLen = std::strlen(aadText);
    size_t msgLen = std::strlen(msgText);

    uint8_t ciphertext[256];
    uint8_t tag[16];
    gcm.encrypt(iv, reinterpret_cast<const uint8_t*>(aadText), aadLen,
                reinterpret_cast<const uint8_t*>(msgText), msgLen,
                ciphertext, tag);

    printHex("Test 5 ciphertext", ciphertext, msgLen);
    printHex("Test 5 tag       ", tag, 16);

    uint8_t decrypted[256];
    bool validTag = gcm.decrypt(iv, reinterpret_cast<const uint8_t*>(aadText), aadLen,
                                 ciphertext, msgLen, tag, decrypted);
    decrypted[msgLen] = '\0';
    std::printf("Test 5 decrypted text: %s\n", decrypted);
    std::printf("Test 5 (tag verification on correct data):             %s\n", validTag ? "PASS" : "FAIL");

    uint8_t tamperedTag[16];
    std::memcpy(tamperedTag, tag, 16);
    tamperedTag[0] = static_cast<uint8_t>(tamperedTag[0] ^ 0x01);
    bool tamperedValid = gcm.decrypt(iv, reinterpret_cast<const uint8_t*>(aadText), aadLen,
                                      ciphertext, msgLen, tamperedTag, decrypted);
    std::printf("Test 6 (rejects tampered tag):                         %s\n", !tamperedValid ? "PASS" : "FAIL");

    uint8_t tamperedCiphertext[256];
    std::memcpy(tamperedCiphertext, ciphertext, msgLen);
    tamperedCiphertext[0] = static_cast<uint8_t>(tamperedCiphertext[0] ^ 0x01);
    bool tamperedCtValid = gcm.decrypt(iv, reinterpret_cast<const uint8_t*>(aadText), aadLen,
                                        tamperedCiphertext, msgLen, tag, decrypted);
    std::printf("Test 7 (rejects tampered ciphertext):                  %s\n", !tamperedCtValid ? "PASS" : "FAIL");

    return 0;
}
