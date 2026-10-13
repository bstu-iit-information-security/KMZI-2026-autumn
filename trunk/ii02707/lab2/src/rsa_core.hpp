#pragma once

#include "rsa_math.hpp"
#include <vector>
#include <cstdint>

std::vector<uint8_t> rsa_encrypt_raw(const RSAPublicKey& pub,
                                     const std::vector<uint8_t>& m);

std::vector<uint8_t> rsa_decrypt_blinded(const RSAPublicKey& pub,
                                         const RSAPrivateKey& priv,
                                         const std::vector<uint8_t>& c);