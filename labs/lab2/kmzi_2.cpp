#include <iostream>
#include <iomanip>
#include <cstdint>
#include <string>

#include <openssl/evp.h>
#include <openssl/sha.h>


void sha384_hash(const std::string& message, uint8_t out_hash[SHA384_DIGEST_LENGTH]) {
    unsigned int length = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha384(), nullptr);

    EVP_DigestUpdate(ctx, message.data(), message.size());

    EVP_DigestFinal_ex(ctx, out_hash, &length);
    EVP_MD_CTX_free(ctx);
}


uint64_t ct_mod_inverse(uint64_t q, uint64_t p) {
    uint64_t u = q, v = p;
    uint64_t x1 = 1, x2 = 0;

    for (int i = 0; i < 128; i++) {
        uint64_t u_even = -(uint64_t)(~u & 1);
        uint64_t v_even = -(uint64_t)(~v & 1);
        uint64_t both_odd = (~u_even) & (~v_even);

        uint64_t mask1 = u_even;
        uint64_t mask2 = (~u_even) & v_even;
        uint64_t mask3 = both_odd;

        uint64_t swap_mask = mask3 & (-(uint64_t)(u < v));

        uint64_t u_xor_v = u ^ v;
        u ^= u_xor_v & swap_mask;
        v ^= u_xor_v & swap_mask;

        uint64_t x1_xor_x2 = x1 ^ x2;
        x1 ^= x1_xor_x2 & swap_mask;
        x2 ^= x1_xor_x2 & swap_mask;

        u -= (v & mask3);

        uint64_t underflow = -(uint64_t)(x1 < x2);
        uint64_t x1_sub = x1 - x2 + (p & underflow);
        x1 = (x1 & ~mask3) | (x1_sub & mask3);

        uint64_t halve_u = mask1 | mask3;
        uint64_t halve_v = mask2;

        u >>= (halve_u & 1);

        uint64_t x1_odd = -(uint64_t)(x1 & 1);
        uint64_t x1_halved = (x1 + (p & x1_odd)) >> 1;
        x1 = (x1 & ~halve_u) | (x1_halved & halve_u);

        v >>= (halve_v & 1);

        uint64_t x2_odd = -(uint64_t)(x2 & 1);
        uint64_t x2_halved = (x2 + (p & x2_odd)) >> 1;
        x2 = (x2 & ~halve_v) | (x2_halved & halve_v);
    }

    return x2;
}

void printHex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << "\n";
}

int main() {

    std::string msg = "Hello, Constant-Time RSA!";

    uint8_t hash[SHA384_DIGEST_LENGTH] = { 0 };

    sha384_hash(msg, hash);

    std::cout << "[1] Hashing: \"" << msg << "\"\n";
    std::cout << "SHA-384: ";
    printHex(hash, SHA384_DIGEST_LENGTH);
    std::cout << "\n\n";

    uint64_t q = 17;
    uint64_t p = 3121;

    uint64_t q_inv = ct_mod_inverse(q, p);

    std::cout << "[2] Constant-Time Binary Extended GCD\n";
    std::cout << "q = " << q << ", p = " << p << "\n";
    std::cout << "q_inv = " << q_inv << "\n";
    std::cout << "Test (q * q_inv mod p): " << (q * q_inv) % p << " (must be 1)\n";

    return 0;
}