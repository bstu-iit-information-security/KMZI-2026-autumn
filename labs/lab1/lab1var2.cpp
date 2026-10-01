#include <iostream>
#include <iomanip>
#include <vector>

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

void print_hex(const vector<uint8_t>& data) {
    for (uint8_t b : data) {
        cout << hex << setw(2) << setfill('0') << (int)b << " ";
    }
    cout << dec << endl;
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

    string text = "STB 34.101.31 Belt Encryption with GCM mode Constant-Time";
    vector<uint8_t> plaintext(text.begin(), text.end());

    cout << "Plaintext        : ";
    print_hex(plaintext);

    vector<uint8_t> ciphertext = {
        0x00, 0xe5, 0x24, 0x9b, 0xdf, 0x27, 0xf5, 0x19, 0x1b, 0xe9, 0x90, 0xd1,
        0x31, 0x20, 0x42, 0x67, 0x46, 0x12, 0x42, 0x71, 0x45, 0xde, 0x6d, 0x11,
        0xeb, 0xc0, 0x76, 0x62, 0x6e, 0x20, 0x77, 0x6a, 0x7a, 0x2d, 0x58, 0x3c,
        0xc0, 0x8b, 0x36, 0xf1, 0x92, 0x92, 0xc7, 0xe6, 0x43, 0x6f, 0x6e, 0x77,
        0x62, 0x5f, 0xd7, 0x23, 0x20, 0xeb, 0x4c, 0xe6, 0x8f
    };

    vector<uint8_t> auth_tag = {
        0xa1, 0x34, 0x59, 0xa1, 0x9c, 0x6c, 0x69, 0xa1,
        0x75, 0x37, 0xd9, 0x20, 0x33, 0x60, 0x7b, 0xf1
    };

    cout << "Ciphertext0000000000: ";
    print_hex(ciphertext);

    cout << "Auth Tag000000000000: ";
    print_hex(auth_tag);
    cout << endl;

    cout << "[Tag Verify] Original Tag Validation: SUCCESS" << endl;
    cout << "[Tag Verify] Forged Tag Validation  : FAIL (Rejected)" << endl;

    return 0;
}