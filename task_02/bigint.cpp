#include "bigint.hpp"
#include <stdexcept>

BigInt::BigInt()
{
    mpz_init(value);
}

BigInt::BigInt(unsigned long x)
{
    mpz_init(value);
    mpz_set_ui(value, x);
}

BigInt::BigInt(const BigInt& other)
{
    mpz_init(value);
    mpz_set(value, other.value);
}

BigInt::BigInt(BigInt&& other) noexcept
{
    mpz_init(value);
    mpz_swap(value, other.value);
}

BigInt& BigInt::operator=(const BigInt& other)
{
    if (this != &other) {
        mpz_set(value, other.value);
    }
    return *this;
}

BigInt& BigInt::operator=(BigInt&& other) noexcept
{
    mpz_swap(value, other.value);
    return *this;
}

BigInt::~BigInt()
{
    mpz_clear(value);
}

BigInt BigInt::from_bytes(const uint8_t* data, size_t len)
{
    BigInt r;
    if (len > 0) {
        mpz_import(r.value, len, 1, 1, 1, 0, data);
    }
    return r;
}

void BigInt::to_bytes(uint8_t* out, size_t len) const
{
    const size_t limb_bytes = sizeof(mp_limb_t);
    for (size_t i = 0; i < len; i++) {
        mp_limb_t limb = mpz_getlimbn(value, static_cast<mp_size_t>(i / limb_bytes));
        out[len - 1 - i] = static_cast<uint8_t>((limb >> (8 * (i % limb_bytes))) & 0xFF);
    }
}

size_t BigInt::bit_length() const
{
    if (is_zero()) {
        return 0;
    }
    return mpz_sizeinbase(value, 2);
}

bool BigInt::test_bit(size_t index) const
{
    return mpz_tstbit(value, index) != 0;
}

void BigInt::set_bit(size_t index)
{
    mpz_setbit(value, index);
}

bool BigInt::is_zero() const
{
    return mpz_cmp_ui(value, 0) == 0;
}

bool BigInt::is_odd() const
{
    return mpz_tstbit(value, 0) != 0;
}

int BigInt::compare(const BigInt& other) const
{
    return mpz_cmp(value, other.value);
}

unsigned long BigInt::to_ulong() const
{
    return mpz_get_ui(value);
}

unsigned long BigInt::mod_ulong(unsigned long m) const
{
    return mpz_fdiv_ui(value, m);
}

BigInt BigInt::shifted_left(size_t bits) const
{
    BigInt r;
    mpz_mul_2exp(r.value, value, bits);
    return r;
}

BigInt operator+(const BigInt& a, const BigInt& b)
{
    BigInt r;
    mpz_add(r.raw(), a.raw(), b.raw());
    return r;
}

BigInt operator-(const BigInt& a, const BigInt& b)
{
    BigInt r;
    mpz_sub(r.raw(), a.raw(), b.raw());
    return r;
}

BigInt operator*(const BigInt& a, const BigInt& b)
{
    BigInt r;
    mpz_mul(r.raw(), a.raw(), b.raw());
    return r;
}

BigInt operator/(const BigInt& a, const BigInt& b)
{
    if (b.is_zero()) {
        throw std::domain_error("division by zero");
    }
    BigInt r;
    mpz_fdiv_q(r.raw(), a.raw(), b.raw());
    return r;
}

BigInt operator%(const BigInt& a, const BigInt& b)
{
    if (b.is_zero()) {
        throw std::domain_error("division by zero");
    }
    BigInt r;
    mpz_fdiv_r(r.raw(), a.raw(), b.raw());
    return r;
}
