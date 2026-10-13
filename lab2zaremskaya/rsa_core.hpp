#pragma once

#include "common.hpp"
#include "number_theory.hpp"

#include <cstddef>
#include <cstdint>

namespace rsa {

BigInt rsa_encrypt_raw(const BigInt& m, const KeyPair& kp);
BigInt rsa_decrypt_crt(const BigInt& c, const KeyPair& kp);

struct GarnerDemo {
    BigInt p, q, n, e, d, dp, dq, qinv;
    BigInt m, c, m1, m2, h, recovered;
};

GarnerDemo garner_demo_small();

}  