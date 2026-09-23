#pragma once

#include "common.hpp"

#include <functional>
#include <utility>

namespace rsa {

struct KeyPair {
    BigInt n;
    BigInt e;
    BigInt d;
    BigInt p;
    BigInt q;
    BigInt dp;     // d mod (p-1)
    BigInt dq;     // d mod (q-1)
    BigInt qinv;   // q^{-1} mod p
    BigInt lambda; // λ(N) = lcm(p-1, q-1)
};

using ProgressFn = std::function<void(const char*)>;

BigInt gcd(const BigInt& a, const BigInt& b);

// Расширенный алгоритм Евклида: ax + by = gcd(a, b).
void egcd(const BigInt& a, const BigInt& b, BigInt& g, BigInt& x, BigInt& y);

BigInt mod_inverse(const BigInt& a, const BigInt& m);
BigInt lcm(const BigInt& a, const BigInt& b);

// Учебное двоичное возведение (right-to-left) на базе BigInt::mod_mul.
BigInt mod_exp_binary(const BigInt& base, const BigInt& exp, const BigInt& mod);

// Быстрое модульное возведение (окно Монтгомери внутри BIGNUM).
BigInt mod_exp(const BigInt& base, const BigInt& exp, const BigInt& mod);

bool miller_rabin(const BigInt& n, int rounds);
BigInt generate_prime(int bits, ProgressFn progress = nullptr);
KeyPair generate_keypair(int bits = kModulusBits, ProgressFn progress = nullptr);

bool random_bytes(uint8_t* buf, std::size_t n);

} 