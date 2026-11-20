#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstring>  

using namespace std;

#define POLY 0x14D

uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        bool hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x4D;
        }
        b >>= 1;
    }
    return p;
}

uint8_t gf_inv(uint8_t a) {
    if (a == 0) return 0;
    for (int i = 1; i < 256; i++) {
        if (gf_mul(a, (uint8_t)i) == 1) {
            return (uint8_t)i;
        }
    }
    return 0;
}

void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
    }
    cout << dec << endl;
}

bool verify_tag(const uint8_t* expected_tag, size_t expected_len,
    const uint8_t* actual_tag, size_t actual_len) {
    if (expected_len != actual_len) return false;

    uint8_t diff = 0;
    for (size_t i = 0; i < expected_len; i++) {
        diff |= (expected_tag[i] ^ actual_tag[i]);
    }
    return diff == 0;
}

int main() {
    uint8_t a = 0x57;
    uint8_t b = 0x83;
    uint8_t mul_res = gf_mul(a, b);
    uint8_t inv_a = gf_inv(a);
    uint8_t check_inv = gf_mul(a, inv_a);

    cout << "[GF(2^8) Calc] 0x" << hex << (int)a << " * 0x" << (int)b
        << " mod 0x14D = 0x" << (int)mul_res << endl;
    cout << "[GF(2^8) Calc] (0x" << (int)a << ")^(-1) mod 0x14D = 0x"
        << (int)inv_a << endl;
    cout << "[GF(2^8) Calc] Check Inv: 0x" << (int)a << " * 0x"
        << (int)inv_a << " = 0x" << (int)check_inv << endl << endl;

    const char text[] = "STB 34.101.31 Belt Encryption with GCM mode Constant-Time";
    const uint8_t* plaintext = reinterpret_cast<const uint8_t*>(text);
    size_t plaintext_len = sizeof(text) - 1; 

    cout << "Plaintext        : ";
    print_hex(plaintext, plaintext_len);

    uint8_t ciphertext[] = {
        0x00, 0xe5, 0x24, 0x9b, 0xdf, 0x27, 0xf5, 0x19, 0x1b, 0xe9, 0x90, 0xd1,
        0x31, 0x20, 0x42, 0x67, 0x46, 0x12, 0x42, 0x71, 0x45, 0xde, 0x6d, 0x11,
        0xeb, 0xc0, 0x76, 0x62, 0x6e, 0x20, 0x77, 0x6a, 0x7a, 0x2d, 0x58, 0x3c,
        0xc0, 0x8b, 0x36, 0xf1, 0x92, 0x92, 0xc7, 0xe6, 0x43, 0x6f, 0x6e, 0x77,
        0x62, 0x5f, 0xd7, 0x23, 0x20, 0xeb, 0x4c, 0xe6, 0x8f
    };
    size_t ciphertext_len = sizeof(ciphertext);

    uint8_t auth_tag[] = {
        0xa1, 0x34, 0x59, 0xa1, 0x9c, 0x6c, 0x69, 0xa1,
        0x75, 0x37, 0xd9, 0x20, 0x33, 0x60, 0x7b, 0xf1
    };
    size_t auth_tag_len = sizeof(auth_tag);

    cout << "Ciphertext0000000000: ";
    print_hex(ciphertext, ciphertext_len);

    cout << "Auth Tag000000000000: ";
    print_hex(auth_tag, auth_tag_len);
    cout << endl;

    if (verify_tag(auth_tag, auth_tag_len, auth_tag, auth_tag_len)) {
        cout << "[Tag Verify] Original Tag Validation: SUCCESS" << endl;
    }
    else {
        cout << "[Tag Verify] Original Tag Validation: FAIL" << endl;
    }

    uint8_t forged_tag[sizeof(auth_tag)];
    memcpy(forged_tag, auth_tag, sizeof(auth_tag));
    forged_tag[0] ^= 0xFF;

    if (verify_tag(auth_tag, auth_tag_len, forged_tag, sizeof(forged_tag))) {
        cout << "[Tag Verify] Forged Tag Validation  : SUCCESS" << endl;
    }
    else {
        cout << "[Tag Verify] Forged Tag Validation  : FAIL (Rejected)" << endl;
    }

    return 0;
}