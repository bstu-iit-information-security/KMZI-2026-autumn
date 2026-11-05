#pragma once

#include "bigint.hpp"
#include <cstdint>

struct RSAPublicKey {
    BigInt N;
    BigInt e;
};

struct RSAPrivateKey {
    BigInt N;
    BigInt d;
    
    BigInt p;
    BigInt q;
    BigInt dp;
    BigInt dq;
    BigInt qinv;
};

void rsa_generate_keypair(int modulus_bits,
                          RSAPublicKey& pub,
                          RSAPrivateKey& priv);