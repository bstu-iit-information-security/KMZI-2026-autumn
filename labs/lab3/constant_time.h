#pragma once
#include "bigint.h"

namespace constant_time {
    BigInt mod_pow_constant_time(const BigInt& base, const BigInt& exp, const BigInt& p);
    BigInt mod_inverse_constant_time(const BigInt& a, const BigInt& p);
}