#include "protocols.h"
#include "constant_time.h"

using namespace protocols;
using namespace ec;

std::pair<BigInt, Point> protocols::ecdh_generate_keys(const Curve& curve) {
    BigInt d = random_scalar(curve.q);
    Point Q = scalar_multiply(d, curve.G, curve);
    return {d, Q};
}

Point protocols::ecdh_compute_shared_secret(const BigInt& priv, const Point& pub, const Curve& curve) {
    return scalar_multiply(priv, pub, curve);
}

std::pair<BigInt, BigInt> protocols::ecdsa_sign(const BigInt& hash, const BigInt& priv, const Curve& curve) {
    BigInt k, r, s;
    do {
        k = random_scalar(curve.q);
        Point C = scalar_multiply(k, curve.G, curve);
        r = C.x % curve.q;
        if (r.is_zero()) continue;
        BigInt k_inv = constant_time::mod_inverse_constant_time(k, curve.q);
        BigInt sum = mod_add(hash, mod_mul(r, priv, curve.q), curve.q);
        s = mod_mul(k_inv, sum, curve.q);
    } while (s.is_zero());
    return {r, s};
}

bool protocols::ecdsa_verify(const BigInt& hash,
                             const std::pair<BigInt, BigInt>& sig,
                             const Point& pub,
                             const Curve& curve) {
    BigInt r = sig.first, s = sig.second;
    if (r.is_zero() || r >= curve.q || s.is_zero() || s >= curve.q) return false;
    BigInt w = constant_time::mod_inverse_constant_time(s, curve.q);
    BigInt u1 = mod_mul(hash, w, curve.q);
    BigInt u2 = mod_mul(r, w, curve.q);
    Point C = point_add(scalar_multiply(u1, curve.G, curve),
                        scalar_multiply(u2, pub, curve), curve);
    if (C.is_infinity) return false;
    BigInt v = C.x % curve.q;
    return v == r;
}