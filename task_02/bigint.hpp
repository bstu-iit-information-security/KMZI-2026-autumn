#pragma once
#include <gmp.h>
#include <cstddef>
#include <cstdint>

class BigInt {
public:
    BigInt();
    BigInt(unsigned long x);
    BigInt(const BigInt& other);
    BigInt(BigInt&& other) noexcept;
    BigInt& operator=(const BigInt& other);
    BigInt& operator=(BigInt&& other) noexcept;
    ~BigInt();

    static BigInt from_bytes(const uint8_t* data, size_t len);
    void to_bytes(uint8_t* out, size_t len) const;

    size_t bit_length() const;
    bool test_bit(size_t index) const;
    void set_bit(size_t index);
    bool is_zero() const;
    bool is_odd() const;
    int compare(const BigInt& other) const;
    unsigned long to_ulong() const;
    unsigned long mod_ulong(unsigned long m) const;
    BigInt shifted_left(size_t bits) const;

    mpz_srcptr raw() const { return value; }
    mpz_ptr raw() { return value; }

private:
    mpz_t value;
};

BigInt operator+(const BigInt& a, const BigInt& b);
BigInt operator-(const BigInt& a, const BigInt& b);
BigInt operator*(const BigInt& a, const BigInt& b);
BigInt operator/(const BigInt& a, const BigInt& b);
BigInt operator%(const BigInt& a, const BigInt& b);

inline bool operator==(const BigInt& a, const BigInt& b) { return a.compare(b) == 0; }
inline bool operator!=(const BigInt& a, const BigInt& b) { return a.compare(b) != 0; }
inline bool operator<(const BigInt& a, const BigInt& b) { return a.compare(b) < 0; }
inline bool operator>(const BigInt& a, const BigInt& b) { return a.compare(b) > 0; }
inline bool operator<=(const BigInt& a, const BigInt& b) { return a.compare(b) <= 0; }
inline bool operator>=(const BigInt& a, const BigInt& b) { return a.compare(b) >= 0; }
