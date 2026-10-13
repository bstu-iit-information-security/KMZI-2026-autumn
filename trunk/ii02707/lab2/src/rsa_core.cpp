#include "rsa_core.hpp"
#include <openssl/rand.h>
#include <stdexcept>
#include <algorithm>

static BigInt rsa_decrypt_crt(const BigInt& c, const RSAPrivateKey& priv) {
    BigInt m1 = BigInt::mod_exp(c % priv.p, priv.dp, priv.p);
    BigInt m2 = BigInt::mod_exp(c % priv.q, priv.dq, priv.q);

    BigInt diff = (m1 - m2 + priv.p) % priv.p;
    BigInt h = BigInt::mod_mul(priv.qinv, diff, priv.p);

    return m2 + h * priv.q;
}

static BigInt generate_blinding_r(const BigInt& N) {
    int bits = N.bit_length();
    while (true) {
        BigInt r = BigInt::random_bits(bits - 1);
        if (r.is_zero() || r.is_one()) continue;
        if (BigInt::gcd(r, N) == BigInt(1)) return r;
    }
}

std::vector<uint8_t> rsa_encrypt_raw(const RSAPublicKey& pub,
                                     const std::vector<uint8_t>& m) {
    BigInt M = BigInt::from_bytes(m);
    if (M >= pub.N)
        throw std::runtime_error("rsa_encrypt_raw: m >= N");
    BigInt C = BigInt::mod_exp(M, pub.e, pub.N);
    return C.to_bytes_padded(pub.N.byte_length());
}

std::vector<uint8_t> rsa_decrypt_blinded(const RSAPublicKey& pub,
                                         const RSAPrivateKey& priv,
                                         const std::vector<uint8_t>& c) {
    BigInt C = BigInt::from_bytes(c);
    if (C >= priv.N)
        throw std::runtime_error("rsa_decrypt_blinded: c >= N");

    BigInt r  = generate_blinding_r(priv.N);
    BigInt re = BigInt::mod_exp(r, pub.e, priv.N);
    BigInt cp = BigInt::mod_mul(C, re, priv.N);

    BigInt mp = rsa_decrypt_crt(cp, priv);

    BigInt rinv = BigInt::mod_inv(r, priv.N);
    BigInt m    = BigInt::mod_mul(mp, rinv, priv.N);

    BigInt verify = BigInt::mod_exp(m, pub.e, priv.N);

    if (verify != C) {
        throw std::runtime_error("rsa_decrypt_blinded: fault detected (m^e != c)");
    }

    return m.to_bytes_padded(priv.N.byte_length());
}