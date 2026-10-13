#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <memory>
#include <openssl/bn.h>

class BigInt {
    BIGNUM* bn_;

    void release() {
        if (bn_) { BN_clear_free(bn_); bn_ = nullptr; }
    }

public:
    BigInt();
    explicit BigInt(uint64_t v);
    BigInt(const BigInt& o);
    BigInt(BigInt&& o) noexcept;
    BigInt& operator=(const BigInt& o);
    BigInt& operator=(BigInt&& o) noexcept;
    ~BigInt();

    static BigInt from_bytes(const uint8_t* data, size_t len);
    static BigInt from_bytes(const std::vector<uint8_t>& v);

    std::vector<uint8_t> to_bytes() const;
    std::vector<uint8_t> to_bytes_padded(size_t len) const;

    BigInt operator+(const BigInt& o) const;
    BigInt operator-(const BigInt& o) const;
    BigInt operator*(const BigInt& o) const;
    BigInt operator/(const BigInt& o) const;
    BigInt operator%(const BigInt& o) const;

    BigInt& operator+=(const BigInt& o);
    BigInt& operator-=(const BigInt& o);

    bool operator==(const BigInt& o) const;
    bool operator!=(const BigInt& o) const;
    bool operator<(const BigInt& o) const;
    bool operator>(const BigInt& o) const;
    bool operator<=(const BigInt& o) const;
    bool operator>=(const BigInt& o) const;

    static BigInt mod_exp(const BigInt& base, const BigInt& exp, const BigInt& mod);
    static BigInt mod_inv(const BigInt& a, const BigInt& mod);
    static BigInt mod_mul(const BigInt& a, const BigInt& b, const BigInt& mod);
    static BigInt mod_add(const BigInt& a, const BigInt& b, const BigInt& mod);
    static BigInt mod_sub(const BigInt& a, const BigInt& b, const BigInt& mod);

    static BigInt gcd(const BigInt& a, const BigInt& b);

    int  bit_length() const;
    int  byte_length() const;
    bool is_zero() const;
    bool is_one() const;
    bool is_odd() const;

    bool is_prime(int checks = 40) const;

    static BigInt random_bits(int bits);
    static BigInt random_range(const BigInt& lo, const BigInt& hi);

    const BIGNUM* raw() const { return bn_; }
    BIGNUM*       raw_mut()   { return bn_; }

    std::string to_decimal() const;
    
};