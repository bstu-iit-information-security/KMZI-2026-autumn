#include "rsa_core.hpp"

#include <stdexcept>

#include "bigint_math.hpp"

namespace rsa {

void generate_keypair(PublicKey& pub, PrivateKey& priv, unsigned bits) {
    const mpz_class e = 65537;
    const unsigned half = bits / 2;  // p и q одинаковой битовой длины

    mpz_class p, q, n;
    do {
        p = gen_prime(half, e);
        q = gen_prime(half, e);
        n = p * q;
    } while (p == q || mpz_sizeinbase(n.get_mpz_t(), 2) != bits);

    // lambda(N) = lcm(p-1, q-1) = (p-1)(q-1) / gcd(p-1, q-1)
    mpz_class pm1 = p - 1, qm1 = q - 1;
    mpz_class lambda = pm1 / gcd(pm1, qm1) * qm1;

    mpz_class d;
    if (!mod_inverse(d, e, lambda)) throw std::runtime_error("gcd(e, lambda) != 1");

    priv.n = n;
    priv.e = e;
    priv.d = d;
    priv.p = p;
    priv.q = q;
    mpz_mod(priv.dp.get_mpz_t(), d.get_mpz_t(), pm1.get_mpz_t());  // dp = d mod (p-1)
    mpz_mod(priv.dq.get_mpz_t(), d.get_mpz_t(), qm1.get_mpz_t());  // dq = d mod (q-1)
    if (!mod_inverse(priv.qinv, q, p)) throw std::runtime_error("q not invertible mod p");

    pub.n = n;
    pub.e = e;
}

void rsa_encrypt_raw(mpz_class& c, const mpz_class& m, const PublicKey& pub) {
    if (m < 0 || m >= pub.n) throw std::invalid_argument("m out of range [0, N)");
    // e публична, поэтому число бит = реальная длина e
    const unsigned ebits = static_cast<unsigned>(mpz_sizeinbase(pub.e.get_mpz_t(), 2));
    powm_joye_tun(c, m, pub.e, pub.n, ebits);
}

void rsa_decrypt_crt(mpz_class& m, const mpz_class& c, const PrivateKey& k) {
    // Фиксированное число бит (длина p / q), НЕ реальная длина dp/dq.
    const unsigned pbits = static_cast<unsigned>(mpz_sizeinbase(k.p.get_mpz_t(), 2));
    const unsigned qbits = static_cast<unsigned>(mpz_sizeinbase(k.q.get_mpz_t(), 2));

    // 1) m1 = c^dp mod p,   2) m2 = c^dq mod q
    mpz_class m1, m2;
    powm_joye_tun(m1, c, k.dp, k.p, pbits);
    powm_joye_tun(m2, c, k.dq, k.q, qbits);

    // 3) h = qinv * (m1 - m2) mod p.
    //    Если m1 - m2 < 0, к разности нужно прибавить p. Чтобы не было `if`,
    //    прибавляем p всегда: (m1 - m2 + p) лежит в (0, 2p) и по модулю p
    //    даёт то же самое.
    mpz_class diff = m1 - m2 + k.p;
    mpz_class h = k.qinv * diff;
    mpz_mod(h.get_mpz_t(), h.get_mpz_t(), k.p.get_mpz_t());

    // 4) m = m2 + h * q
    m = m2 + h * k.q;
}

void rsa_decrypt_plain(mpz_class& m, const mpz_class& c, const PrivateKey& k) {
    const unsigned nbits = static_cast<unsigned>(mpz_sizeinbase(k.n.get_mpz_t(), 2));
    powm_joye_tun(m, c, k.d, k.n, nbits);
}

}  // namespace rsa
