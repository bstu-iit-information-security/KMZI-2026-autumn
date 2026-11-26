#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <chrono>
#include <functional>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <openssl/bn.h>
#include <openssl/rand.h>

namespace rsa {
constexpr int kVariant = 5;
constexpr int kModulusBits = 4096;
constexpr std::size_t kModulusBytes = kModulusBits / 8;
constexpr std::size_t kHashLen = 32;
constexpr std::size_t kMaxMessage = kModulusBytes - 2 * kHashLen - 2;
constexpr int kPublicExponent = 65537;
constexpr int kMillerRabinRounds = 12;
constexpr const char* kHashName = "SHA-256";
constexpr const char* kOptimization =
    "Unconditional lHash hash comparison using XOR accumulator";
}  


namespace rsa {
namespace ct {

inline uint32_t barrier(uint32_t x) {
    volatile uint32_t v = x;
    return v;
}

inline uint32_t is_zero(uint32_t x) {
    x = barrier(x);
    uint32_t t = x | (0u - x);
    return barrier(~t) >> 31u;
}

inline uint32_t mask_from_bit(uint32_t bit) {
    return barrier(0u - (bit & 1u));
}

inline uint32_t eq(uint32_t a, uint32_t b) {
    return mask_from_bit(is_zero(a ^ b));
}

inline uint32_t eq_u8(uint8_t a, uint8_t b) {
    return eq(static_cast<uint32_t>(a), static_cast<uint32_t>(b));
}

inline uint32_t select(uint32_t mask, uint32_t a, uint32_t b) {
    mask = barrier(mask);
    return (mask & a) | (~mask & b);
}

inline uint8_t select_u8(uint32_t mask, uint8_t a, uint8_t b) {
    return static_cast<uint8_t>(select(mask, a, b));
}

inline uint32_t lt(uint32_t a, uint32_t b) {
    return mask_from_bit((a - b) >> 31);
}

inline uint8_t xor_accum(const uint8_t* a, const uint8_t* b, std::size_t n) {
    uint8_t acc = 0;
    for (std::size_t i = 0; i < n; ++i) {
        acc = static_cast<uint8_t>(acc | (a[i] ^ b[i]));
    }
    volatile uint8_t v = acc;
    return v;
}

}  
}  

namespace rsa {

class BnError : public std::runtime_error {
public:
    explicit BnError(const char* what) : std::runtime_error(what) {}
};

class BigInt {
public:
    BigInt();
    BigInt(const BigInt& other);
    BigInt(BigInt&& other) noexcept;
    explicit BigInt(unsigned long v);
    ~BigInt();

    BigInt& operator=(const BigInt& other);
    BigInt& operator=(BigInt&& other) noexcept;

    static BigInt from_dec(const char* s);
    static BigInt from_hex(const char* s);
    static BigInt from_bytes_be(const uint8_t* p, std::size_t n);
    static BigInt random_bits(int bits, bool top_odd);

    std::string to_dec() const;
    std::string to_hex() const;
    std::vector<uint8_t> to_bytes_be(std::size_t width) const;
    void to_bytes_be(uint8_t* out, std::size_t width) const;

    int bit_length() const;
    int byte_length() const;
    bool is_zero() const;
    bool is_odd() const;
    bool bit_set(int i) const;
    int cmp(const BigInt& o) const;

    BigInt add(const BigInt& o) const;
    BigInt sub(const BigInt& o) const;
    BigInt mul(const BigInt& o) const;
    BigInt div(const BigInt& o) const;
    BigInt mod(const BigInt& m) const;
    BigInt mod_add(const BigInt& o, const BigInt& m) const;
    BigInt mod_sub(const BigInt& o, const BigInt& m) const;
    BigInt mod_mul(const BigInt& o, const BigInt& m) const;

    BIGNUM* raw() { return n_; }
    const BIGNUM* raw() const { return n_; }

private:
    BIGNUM* n_;
    static BN_CTX* ctx();
};

}  


namespace rsa {

constexpr std::size_t kSha256Len = 32;

void sha256(const uint8_t* data, std::size_t len, uint8_t out[kSha256Len]);
bool sha256_selftest();

}  


namespace rsa {

struct KeyPair {
    BigInt n;
    BigInt e;
    BigInt d;
    BigInt p;
    BigInt q;
    BigInt dp;
    BigInt dq;
    BigInt qinv;
    BigInt lambda;
};

using ProgressFn = std::function<void(const char*)>;

BigInt gcd(const BigInt& a, const BigInt& b);

void egcd(const BigInt& a, const BigInt& b, BigInt& g, BigInt& x, BigInt& y);

BigInt mod_inverse(const BigInt& a, const BigInt& m);
BigInt lcm(const BigInt& a, const BigInt& b);

BigInt mod_exp_binary(const BigInt& base, const BigInt& exp, const BigInt& mod);

BigInt mod_exp(const BigInt& base, const BigInt& exp, const BigInt& mod);

bool miller_rabin(const BigInt& n, int rounds);
BigInt generate_prime(int bits, ProgressFn progress = nullptr);
KeyPair generate_keypair(int bits = kModulusBits, ProgressFn progress = nullptr);

bool random_bytes(uint8_t* buf, std::size_t n);

} 


namespace rsa {

BigInt rsa_encrypt_raw(const BigInt& m, const KeyPair& kp);
BigInt rsa_decrypt_crt(const BigInt& c, const KeyPair& kp);

struct GarnerDemo {
    BigInt p, q, n, e, d, dp, dq, qinv;
    BigInt m, c, m1, m2, h, recovered;
};

GarnerDemo garner_demo_small();

}  


namespace rsa {

struct OaepResult {
    bool ok;
    std::size_t len;
    uint8_t msg[kModulusBytes];
};

class OaepEngine {
public:
    OaepEngine() = default;

    bool encode(const uint8_t* msg, std::size_t msg_len, uint8_t em[kModulusBytes]);
    OaepResult decode(const uint8_t em[kModulusBytes]);

    static uint8_t lhash_xor_accum(const uint8_t* a, const uint8_t* b);

private:
    void hash(const uint8_t* data, std::size_t len, uint8_t out[kHashLen]);
    void mgf1(const uint8_t* seed, std::size_t seed_len, uint8_t* mask, std::size_t mask_len);

    uint8_t lhash_[kHashLen];
    uint8_t seed_[kHashLen];
    uint8_t db_[kModulusBytes];
    uint8_t masked_db_[kModulusBytes];
    uint8_t db_mask_[kModulusBytes];
    uint8_t seed_mask_[kHashLen];
    uint8_t mgf_block_[kModulusBytes + 4];
    uint8_t mgf_hash_[kHashLen];
};

bool rsa_oaep_encrypt(const uint8_t* msg, std::size_t msg_len, const KeyPair& kp,
                      uint8_t ct[kModulusBytes]);
OaepResult rsa_oaep_decrypt(const uint8_t ct[kModulusBytes], const KeyPair& kp);

} 