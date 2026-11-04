#pragma once
#include <boost/multiprecision/cpp_int.hpp>

namespace rsa {

using BigInt = boost::multiprecision::cpp_int;

struct ExtendedGcd { BigInt gcd, x, y; };

ExtendedGcd extended_gcd(const BigInt& a, const BigInt& b);
BigInt mod_inverse(const BigInt& a, const BigInt& m);
BigInt mod_pow(const BigInt& base, const BigInt& exp, const BigInt& mod);
bool is_prime(const BigInt& n, int rounds = 40);
BigInt generate_prime(int bits);

struct RsaKeys { BigInt n, e, d, p, q, dp, dq, qinv; };
RsaKeys generate_keys(int bits = 2048);

}
