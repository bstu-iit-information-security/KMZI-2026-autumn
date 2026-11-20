#include "ec_curve.h"
#include <sstream>

namespace ecc {

BigInt from_hex(const std::string& s) {
    BigInt x = 0;
    for (char ch : s) {
        int d = (ch >= '0' && ch <= '9') ? ch - '0' : (std::tolower(ch) - 'a' + 10);
        x = x * 16 + d;
    }
    return x;
}

std::string to_hex(const BigInt& x) {
    std::stringstream ss;
    ss << std::hex << x;
    return ss.str();
}

std::array<std::uint8_t, 32> to_bytes32(const BigInt& x) {
    std::array<std::uint8_t, 32> b{};
    BigInt t = x;
    for (int i = 31; i >= 0; --i) {
        b[i] = static_cast<std::uint8_t>((t & 0xFF).convert_to<unsigned>());
        t >>= 8;
    }
    return b;
}

CurveParams load_secp256k1() {
    CurveParams c;
    c.p  = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    c.a  = from_hex("0000000000000000000000000000000000000000000000000000000000000000");
    c.b  = from_hex("0000000000000000000000000000000000000000000000000000000000000007");
    c.gx = from_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    c.gy = from_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    c.q  = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    return c;
}

Point point_neg(const Point& P, const CurveParams& c) {
    if (P.inf) return P;
    Point R; R.x = P.x; R.y = (c.p - P.y) % c.p; return R;
}

Point point_double(const Point& P, const CurveParams& c) {
    if (P.inf || P.y == 0) return Point{};
    BigInt num = (3 * P.x * P.x + c.a) % c.p; if (num < 0) num += c.p;
    BigInt den = (2 * P.y) % c.p;
    const BigInt s = (num * rsa::mod_inverse(den, c.p)) % c.p;
    BigInt x3 = (s * s - 2 * P.x) % c.p; if (x3 < 0) x3 += c.p;
    BigInt y3 = (s * (P.x - x3) - P.y) % c.p; if (y3 < 0) y3 += c.p;
    Point R; R.x = x3; R.y = y3; return R;
}

Point point_add(const Point& P, const Point& Q, const CurveParams& c) {
    if (P.inf) return Q;
    if (Q.inf) return P;
    if (P.x == Q.x) {
        if ((P.y + Q.y) % c.p == 0) return Point{}; // P = -Q
        return point_double(P, c);                  // P = Q
    }
    BigInt dx = (Q.x - P.x) % c.p; if (dx < 0) dx += c.p;
    BigInt dy = (Q.y - P.y) % c.p; if (dy < 0) dy += c.p;
    const BigInt s = (dy * rsa::mod_inverse(dx, c.p)) % c.p;
    BigInt x3 = (s * s - P.x - Q.x) % c.p; if (x3 < 0) x3 += c.p;
    BigInt y3 = (s * (P.x - x3) - P.y) % c.p; if (y3 < 0) y3 += c.p;
    Point R; R.x = x3; R.y = y3; return R;
}

Point scalar_mult(const BigInt& k, const Point& P, const CurveParams& c) {
    Point R;
    if (k == 0) return R;
    const int top = static_cast<int>(boost::multiprecision::msb(k));
    for (int i = top; i >= 0; --i) {
        R = point_double(R, c);
        if (boost::multiprecision::bit_test(k, i)) R = point_add(R, P, c);
    }
    return R;
}

}