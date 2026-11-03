#pragma once

#include "rsa_math.hpp"

class RsaCore {
public:
    static bool encrypt(Bn& cipher, const Bn& message, const Bn& exponent, const Bn& modulus);
    static bool decrypt(Bn& message, const Bn& cipher, const RsaKey& key);
};
