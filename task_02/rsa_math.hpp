#pragma once
#include "bigint.hpp"
#include <cstddef>

struct PublicKey {
    BigInt n;
    BigInt e;
};

struct PrivateKey {
    BigInt n;
    BigInt d;
    BigInt p;
    BigInt q;
    BigInt dp;
    BigInt dq;
    BigInt qinv;
};

struct KeyPair {
    PublicKey pub;
    PrivateKey priv;
};

BigInt ext_gcd(const BigInt& a, const BigInt& b, BigInt& x, BigInt& y);
BigInt gcd(const BigInt& a, const BigInt& b);
BigInt lcm(const BigInt& a, const BigInt& b);
BigInt mod_inverse(const BigInt& a, const BigInt& m);
BigInt mod_pow(const BigInt& base, const BigInt& exponent, const BigInt& modulus);
bool is_probable_prime(const BigInt& n, int rounds);
BigInt generate_prime(size_t bits);
KeyPair generate_keypair(size_t modulus_bits, unsigned long public_exponent = 65537);
