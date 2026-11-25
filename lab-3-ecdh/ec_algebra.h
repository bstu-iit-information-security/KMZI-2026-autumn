// ec_algebra.hpp
#pragma once
#include <gmpxx.h>
#include <string>
#include <stdexcept>

struct Point {
    mpz_class x, y;
    bool is_infinity = false;

    Point() : x(0), y(0), is_infinity(true) {}
    Point(const mpz_class& x_, const mpz_class& y_) : x(x_), y(y_), is_infinity(false) {}

    bool operator==(const Point& o) const {
        if (is_infinity && o.is_infinity) return true;
        if (is_infinity || o.is_infinity) return false;
        return x == o.x && y == o.y;
    }
    bool operator!=(const Point& o) const { return !(*this == o); }
};

struct CurveParams {
    mpz_class p, a, b, q;
    Point G;
    static CurveParams from_hex() {
        CurveParams c;
        c.p = mpz_class("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43", 16);
        c.a = mpz_class("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF40", 16);
        c.b = mpz_class("77CE6C1515F3A8EDD2C13AABE4D8FBBE4CF55069978B9253B22E7D6BD69C03F1", 16);
        c.q = mpz_class("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD95C8ED60DFB4DFC7E5ABF99263D6607", 16);
        mpz_class Gx("0", 16);
        mpz_class Gy("6BF7FC3CFB16D69F5CE4C9A351D6835D78913966C408F6521E29CF1804516A93", 16);
        c.G = Point(Gx, Gy);
        return c;
    }
};

inline mpz_class mod_add(const mpz_class& a, const mpz_class& b, const mpz_class& p) {
    mpz_class r, t = a + b;
    mpz_mod(r.get_mpz_t(), t.get_mpz_t(), p.get_mpz_t());
    return r;
}
inline mpz_class mod_sub(const mpz_class& a, const mpz_class& b, const mpz_class& p) {
    mpz_class r, t = a - b;
    mpz_mod(r.get_mpz_t(), t.get_mpz_t(), p.get_mpz_t());
    return r;
}
inline mpz_class mod_mul(const mpz_class& a, const mpz_class& b, const mpz_class& p) {
    mpz_class r, t = a * b;
    mpz_mod(r.get_mpz_t(), t.get_mpz_t(), p.get_mpz_t());
    return r;
}

inline mpz_class mod_inv(const mpz_class& a, const mpz_class& p) {
    mpz_class inv;
    if (mpz_invert(inv.get_mpz_t(), a.get_mpz_t(), p.get_mpz_t()) == 0)
        throw std::runtime_error("mod_inv: обратного элемента не существует");
    return inv;
}

inline bool is_on_curve(const Point& P, const CurveParams& C) {
    if (P.is_infinity) return true;
    mpz_class lhs = mod_mul(P.y, P.y, C.p);
    mpz_class rhs = mod_add(
        mod_add(mod_mul(mod_mul(P.x, P.x, C.p), P.x, C.p), mod_mul(C.a, P.x, C.p), C.p),
        C.b, C.p);
    return lhs == rhs;
}

inline Point point_double(const Point& P, const CurveParams& C) {
    if (P.is_infinity) return P;
    if (P.y == 0) return Point();

    mpz_class num = mod_add(mod_mul(mpz_class(3) * P.x * P.x, 1, C.p), C.a, C.p);
    mpz_class den = mod_mul(mpz_class(2), P.y, C.p);
    mpz_class s = mod_mul(num, mod_inv(den, C.p), C.p);
    mpz_class x3 = mod_sub(mod_mul(s, s, C.p), mpz_class(2) * P.x, C.p);
    mpz_class y3 = mod_sub(mod_mul(s, mod_sub(P.x, x3, C.p), C.p), P.y, C.p);

    return Point(x3, y3);
}

inline Point point_add(const Point& P, const Point& Q, const CurveParams& C) {
    if (P.is_infinity) return Q;
    if (Q.is_infinity) return P;
    if (P == Q) return point_double(P, C);
    if (P.x == Q.x) return Point();

    mpz_class num = mod_sub(Q.y, P.y, C.p);
    mpz_class den = mod_sub(Q.x, P.x, C.p);
    mpz_class s = mod_mul(num, mod_inv(den, C.p), C.p);
    mpz_class x3 = mod_sub(mod_sub(mod_mul(s, s, C.p), P.x, C.p), Q.x, C.p);
    mpz_class y3 = mod_sub(mod_mul(s, mod_sub(P.x, x3, C.p), C.p), P.y, C.p);

    return Point(x3, y3);
}

inline Point scalar_multiply(const mpz_class& k, const Point& P, const CurveParams& C) {
    if (k == 0 || P.is_infinity) return Point();
    Point R;
    Point Q = P;
    mpz_class kk = k;
    while (kk > 0) {
        if (mpz_tstbit(kk.get_mpz_t(), 0)) {
            R = point_add(R, Q, C);
        }
        Q = point_double(Q, C);
        kk >>= 1;
    }
    return R;
}