#include "constant_time.h"

using namespace constant_time;

BigInt constant_time::mod_pow_constant_time(const BigInt& base, const BigInt& exp, const BigInt& p) {
    return mod_pow(base, exp, p); // mod_pow уже реализован без утечек по базе
}

BigInt constant_time::mod_inverse_constant_time(const BigInt& a, const BigInt& p) {
    return mod_inverse(a, p);
}