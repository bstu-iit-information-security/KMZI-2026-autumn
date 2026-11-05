#include "protocols.h"
#include <fstream>
#include <cstring>

EcdhKeyPair ecdh_generate_keypair(const CurveParams& C) {
    EcdhKeyPair kp;
    kp.d = generate_scalar_ct(C.q, 100);
    kp.Q = secure_multiply(kp.d, C.G, C);
    return kp;
}

mpz_class ecdh_shared_secret(const mpz_class& d, const Point& Q_peer,
                             const CurveParams& C) {
    if (!is_on_curve(Q_peer, C))
        throw std::invalid_argument("ECDH: открытый ключ не на кривой");
    if (d <= 0 || d >= C.q)
        throw std::invalid_argument("ECDH: d вне [1,q-1]");

    Point K = secure_multiply(d, Q_peer, C);
    if (K.is_infinity)
        throw std::runtime_error("ECDH: общий секрет — бесконечность");

    mpz_class result = K.x;
    secure_clear_mpz(K.x);
    secure_clear_mpz(K.y);
    return result;
}

Signature sign(const mpz_class& e, const mpz_class& d, const CurveParams& C) {
    if (d <= 0 || d >= C.q)
        throw std::invalid_argument("sign: d вне [1,q-1]");

    mpz_class e_mod = e % C.q;
    if (e_mod < 0) e_mod += C.q;
    if (e_mod == 0)
        throw std::invalid_argument("sign: e ≡ 0 mod q — инверсия невозможна");

    for (int attempt = 0; attempt < 100; ++attempt) {
        mpz_class k = generate_scalar_ct(C.q, 100);
        Point Cpoint = secure_multiply(k, C.G, C);

        if (Cpoint.is_infinity) {
            secure_clear_mpz(k);
            continue;
        }

        mpz_class r = Cpoint.x % C.q;
        if (r < 0) r += C.q;

        if (r == 0) {
            secure_clear_mpz(k);
            secure_clear_mpz(Cpoint.x);
            secure_clear_mpz(Cpoint.y);
            continue;
        }

        // s = (r*d + k*e) mod q
        mpz_class s = mod_add(mod_mul(r, d, C.q),
                              mod_mul(k, e_mod, C.q), C.q);

        if (s == 0) {
            secure_clear_mpz(k);
            secure_clear_mpz(r);
            continue;
        }

        secure_clear_mpz(k);
        secure_clear_mpz(e_mod);
        secure_clear_mpz(Cpoint.x);
        secure_clear_mpz(Cpoint.y);

        return Signature{r, s};
    }
    throw std::runtime_error("sign: 100 попыток — r или s всё время 0");
}

bool verify(const mpz_class& e, const Signature& sig,
            const Point& Q, const CurveParams& C) {
    if (sig.r <= 0 || sig.r >= C.q) return false;
    if (sig.s <= 0 || sig.s >= C.q) return false;
    if (!is_on_curve(Q, C))         return false;

    mpz_class e_mod = e % C.q;
    if (e_mod < 0) e_mod += C.q;
    if (e_mod == 0) return false;

    mpz_class v;
    if (mpz_invert(v.get_mpz_t(), e_mod.get_mpz_t(), C.q.get_mpz_t()) == 0)
        return false;

    mpz_class z1 = mod_mul(sig.s, v, C.q);
    mpz_class z2 = mod_mul(-sig.r, v, C.q);
    if (z2 < 0) z2 += C.q;

    Point C1 = scalar_multiply(z1, C.G, C);
    Point C2 = scalar_multiply(z2, Q, C);
    Point Cprime = point_add(C1, C2, C);
    if (Cprime.is_infinity) return false;

    mpz_class R = Cprime.x % C.q;
    if (R < 0) R += C.q;
    return (R == sig.r);
}