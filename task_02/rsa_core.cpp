#include "rsa_core.hpp"
#include <stdexcept>

BigInt rsa_encrypt_raw(const BigInt& m, const PublicKey& key)
{
    if (m >= key.n) {
        throw std::invalid_argument("message representative out of range");
    }
    return mod_pow(m, key.e, key.n);
}

BigInt rsa_decrypt_plain(const BigInt& c, const PrivateKey& key)
{
    if (c >= key.n) {
        throw std::invalid_argument("ciphertext representative out of range");
    }
    return mod_pow(c, key.d, key.n);
}

BigInt rsa_decrypt_crt(const BigInt& c, const PrivateKey& key)
{
    if (c >= key.n) {
        throw std::invalid_argument("ciphertext representative out of range");
    }
    BigInt m1 = mod_pow(c % key.p, key.dp, key.p);
    BigInt m2 = mod_pow(c % key.q, key.dq, key.q);
    BigInt diff = m1 - m2;
    if (diff < BigInt(0)) {
        diff = diff + key.p;
    }
    BigInt h = (key.qinv * diff) % key.p;
    return m2 + h * key.q;
}

bool rsa_encrypt_block(const uint8_t* in, size_t k, uint8_t* out, const PublicKey& key)
{
    BigInt m = BigInt::from_bytes(in, k);
    if (m >= key.n) {
        return false;
    }
    BigInt c = rsa_encrypt_raw(m, key);
    c.to_bytes(out, k);
    return true;
}

bool rsa_decrypt_block(const uint8_t* in, size_t k, uint8_t* out, const PrivateKey& key)
{
    BigInt c = BigInt::from_bytes(in, k);
    if (c >= key.n) {
        return false;
    }
    BigInt m = rsa_decrypt_crt(c, key);
    m.to_bytes(out, k);
    return true;
}
