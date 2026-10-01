#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/bn.h>

namespace rsa {

constexpr int kVariant = 7;
constexpr int kModulusBits = 2048;
constexpr std::size_t kModulusBytes = kModulusBits / 8;                // 256
constexpr std::size_t kHashLen = 64;                                   // SHA-512
constexpr std::size_t kMaxMessage = kModulusBytes - 2 * kHashLen - 2;  // 126
constexpr int kPublicExponent = 65537;
constexpr int kMillerRabinRounds = 12;
constexpr const char* kHashName = "SHA-512";
constexpr const char* kOptimization =
    "Constant-time извлечение сообщения из DB "
    "(безусловный поиск разделителя 0x01)";

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

// a < b для значений < 2^31 (длины OAEP-блоков).
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

constexpr std::size_t kSha512Len = 64;

void sha512(const uint8_t* data, std::size_t len, uint8_t out[kSha512Len]);
bool sha512_selftest();

} 