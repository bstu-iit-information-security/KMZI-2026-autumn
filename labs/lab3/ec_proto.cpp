#include "ec_proto.h"
#include "ec_ct.h"
#include <random>
#include <stdexcept>

namespace ecc {

BigInt generate_nonce(const CurveParams& c) {
    static std::mt19937_64 gen{std::random_device{}()};
    BigInt x = 0;
    for (int i = 0; i < 4; ++i) x = (x << 64) | BigInt(gen());
    return x % (c.q - 1) + 1; // [1, q-1]
}

KeyPair keygen(const CurveParams& c) {
    KeyPair kp;
    kp.d = generate_nonce(c);
    Point G; G.x = c.gx; G.y = c.gy; G.inf = false;
    kp.Q = ct::secure_multiply(kp.d, G, c);
    return kp;
}

BigInt ecdh_shared(const BigInt& d, const Point& Q_other, const CurveParams& c) {
    return ct::secure_multiply(d, Q_other, c).x; // общий секрет = координата x
}

Signature ecdsa_sign(const BigInt& e, const BigInt& d, const BigInt& k, const CurveParams& c) {
    Point G; G.x = c.gx; G.y = c.gy; G.inf = false;
    const Point C = ct::secure_multiply(k, G, c);
    const BigInt r = C.x % c.q;
    if (r == 0) throw std::runtime_error("ecdsa_sign: r = 0");
    const BigInt s = (rsa::mod_inverse(k, c.q) * (e + r * d)) % c.q;
    if (s == 0) throw std::runtime_error("ecdsa_sign: s = 0");
    return {r, s};
}

bool ecdsa_verify(const BigInt& e, const Signature& sig, const Point& Q, const CurveParams& c) {
    if (sig.r <= 0 || sig.r >= c.q || sig.s <= 0 || sig.s >= c.q) return false;
    Point G; G.x = c.gx; G.y = c.gy; G.inf = false;
    const BigInt w = rsa::mod_inverse(sig.s, c.q);
    const BigInt u1 = (e * w) % c.q;
    const BigInt u2 = (sig.r * w) % c.q;
    // Данные публичные — constant-time не требуется, базовое умножение модуля 1
    const Point C2 = point_add(scalar_mult(u1, G, c), scalar_mult(u2, Q, c), c);
    if (C2.inf) return false;
    return ct::secure_compare(C2.x % c.q, sig.r);
}

}