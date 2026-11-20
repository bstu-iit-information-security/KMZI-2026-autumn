#include "rsa_math.hpp"
#include <openssl/rand.h>
#include <stdexcept>

static BigInt lcm(const BigInt& a, const BigInt& b) {
    BigInt g = BigInt::gcd(a, b);
    return (a / g) * b;
}

static BigInt generate_prime(int bits) {
    while (true) {
        BigInt cand = BigInt::random_bits(bits);
        BN_set_bit(cand.raw_mut(), bits - 1);
        BN_set_bit(cand.raw_mut(), 0);

        if (cand.is_prime(40)) return cand;
    }
}

void rsa_generate_keypair(int modulus_bits,
                          RSAPublicKey& pub,
                          RSAPrivateKey& priv) {
    if (modulus_bits < 1024 || modulus_bits % 2 != 0)
        throw std::invalid_argument("modulus_bits must be even and >= 1024");

    int half = modulus_bits / 2;
    BigInt p, q;

    p = generate_prime(half);
    do {
        q = generate_prime(half);
    } while (p == q);

    if (p < q) std::swap(p, q);

    BigInt N = p * q;

    BigInt p1 = p - BigInt(1);
    BigInt q1 = q - BigInt(1);
    BigInt lambda = lcm(p1, q1);

    BigInt e(uint64_t(65537));
    if (BigInt::gcd(e, lambda) != BigInt(1))
        throw std::runtime_error("e not coprime with lambda(N)");

    BigInt d = BigInt::mod_inv(e, lambda);

    BigInt dp   = d % p1;
    BigInt dq   = d % q1;
    BigInt qinv = BigInt::mod_inv(q, p);

    pub.N = N;  pub.e = e;
    priv.N = N; priv.d = d;
    priv.p = p; priv.q = q;
    priv.dp = dp; priv.dq = dq; priv.qinv = qinv;
}