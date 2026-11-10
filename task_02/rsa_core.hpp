#pragma once
#include "rsa_math.hpp"
#include <cstddef>
#include <cstdint>

BigInt rsa_encrypt_raw(const BigInt& m, const PublicKey& key);
BigInt rsa_decrypt_plain(const BigInt& c, const PrivateKey& key);
BigInt rsa_decrypt_crt(const BigInt& c, const PrivateKey& key);

bool rsa_encrypt_block(const uint8_t* in, size_t k, uint8_t* out, const PublicKey& key);
bool rsa_decrypt_block(const uint8_t* in, size_t k, uint8_t* out, const PrivateKey& key);
