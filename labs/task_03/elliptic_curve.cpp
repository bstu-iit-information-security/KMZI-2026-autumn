#include "elliptic_curve.hpp"

#include <stdexcept>

namespace BigIntUtils {

unsigned hexDigit(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A' + 10);
    throw std::invalid_argument("Non-hex character");
}

BigInt fromHex(const std::string& hex) {
    BigInt value = 0;
    for (char c : hex) {
        value <<= 4;
        value += hexDigit(c);
    }
    return value;
}

BigInt mod(const BigInt& x, const BigInt& m) {
    BigInt r = x % m;
    if (r < 0) r += m;
    return r;
}

BigInt inverse(const BigInt& a, const BigInt& m) {
    BigInt oldR = mod(a, m);
    BigInt r = m;
    BigInt oldT = 1;
    BigInt t = 0;

    while (r != 0) {
        BigInt q = oldR / r;
        BigInt nextR = oldR - q * r;
        oldR = r;
        r = nextR;
        BigInt nextT = oldT - q * t;
        oldT = t;
        t = nextT;
    }

    if (oldR != 1) {
        throw std::runtime_error("Inverse does not exist");
    }

    return mod(oldT, m);
}

std::string toFixedHex(BigInt value, std::size_t bytes) {
    static constexpr char DIGITS[] = "0123456789ABCDEF";
    std::string out(bytes * 2, '0');

    for (std::size_t i = 0; i < bytes * 2; ++i) {
        const unsigned nibble = static_cast<unsigned>(value & 0xF);
        out[out.size() - 1 - i] = DIGITS[nibble];
        value >>= 4;
    }

    return out;
}

}

EllipticCurve::EllipticCurve(const std::string& pHex,
                             const std::string& aHex,
                             const std::string& bHex,
                             const std::string& qHex,
                             const std::string& gxHex,
                             const std::string& gyHex)
    : p_(BigIntUtils::fromHex(pHex)),
      a_(BigIntUtils::fromHex(aHex)),
      b_(BigIntUtils::fromHex(bHex)),
      q_(BigIntUtils::fromHex(qHex)),
      G_{BigIntUtils::fromHex(gxHex), BigIntUtils::fromHex(gyHex), BigInt(1)} {}

const BigInt& EllipticCurve::p() const {
    return p_;
}

const BigInt& EllipticCurve::q() const {
    return q_;
}

const JacobianPoint& EllipticCurve::generator() const {
    return G_;
}

JacobianPoint EllipticCurve::infinity() const {
    return {BigInt(1), BigInt(1), BigInt(0)};
}

bool EllipticCurve::isInfinity(const JacobianPoint& P) const {
    return BigIntUtils::mod(P.Z, p_) == 0;
}

JacobianPoint EllipticCurve::fromAffine(const BigInt& x, const BigInt& y) const {
    return {BigIntUtils::mod(x, p_), BigIntUtils::mod(y, p_), BigInt(1)};
}

AffinePoint EllipticCurve::toAffine(const JacobianPoint& P) const {
    if (isInfinity(P)) {
        return {0, 0, true};
    }

    const BigInt zInv = BigIntUtils::inverse(P.Z, p_);
    const BigInt zInv2 = BigIntUtils::mod(zInv * zInv, p_);
    const BigInt zInv3 = BigIntUtils::mod(zInv2 * zInv, p_);
    const BigInt x = BigIntUtils::mod(P.X * zInv2, p_);
    const BigInt y = BigIntUtils::mod(P.Y * zInv3, p_);
    return {x, y, false};
}

bool EllipticCurve::isOnCurveAffine(const AffinePoint& P) const {
    if (P.infinity) return true;
    const BigInt left = BigIntUtils::mod(P.y * P.y, p_);
    const BigInt right = BigIntUtils::mod(P.x * P.x * P.x + a_ * P.x + b_, p_);
    return left == right;
}

JacobianPoint EllipticCurve::doublePoint(const JacobianPoint& P) const {
    if (isInfinity(P)) return P;
    if (BigIntUtils::mod(P.Y, p_) == 0) return infinity();

    const BigInt y2 = BigIntUtils::mod(P.Y * P.Y, p_);
    const BigInt y4 = BigIntUtils::mod(y2 * y2, p_);
    const BigInt z2 = BigIntUtils::mod(P.Z * P.Z, p_);
    const BigInt z4 = BigIntUtils::mod(z2 * z2, p_);
    const BigInt S = BigIntUtils::mod(4 * P.X * y2, p_);
    const BigInt M = BigIntUtils::mod(3 * P.X * P.X + a_ * z4, p_);
    const BigInt X3 = BigIntUtils::mod(M * M - 2 * S, p_);
    const BigInt Y3 = BigIntUtils::mod(M * (S - X3) - 8 * y4, p_);
    const BigInt Z3 = BigIntUtils::mod(2 * P.Y * P.Z, p_);

    return {X3, Y3, Z3};
}

JacobianPoint EllipticCurve::add(const JacobianPoint& P, const JacobianPoint& Q) const {
    if (isInfinity(P)) return Q;
    if (isInfinity(Q)) return P;

    const BigInt z1z1 = BigIntUtils::mod(P.Z * P.Z, p_);
    const BigInt z2z2 = BigIntUtils::mod(Q.Z * Q.Z, p_);
    const BigInt U1 = BigIntUtils::mod(P.X * z2z2, p_);
    const BigInt U2 = BigIntUtils::mod(Q.X * z1z1, p_);
    const BigInt S1 = BigIntUtils::mod(P.Y * Q.Z * z2z2, p_);
    const BigInt S2 = BigIntUtils::mod(Q.Y * P.Z * z1z1, p_);

    if (U1 == U2) {
        if (S1 != S2) return infinity();
        return doublePoint(P);
    }

    const BigInt H = BigIntUtils::mod(U2 - U1, p_);
    const BigInt R = BigIntUtils::mod(S2 - S1, p_);
    const BigInt H2 = BigIntUtils::mod(H * H, p_);
    const BigInt H3 = BigIntUtils::mod(H2 * H, p_);
    const BigInt U1H2 = BigIntUtils::mod(U1 * H2, p_);
    const BigInt X3 = BigIntUtils::mod(R * R - H3 - 2 * U1H2, p_);
    const BigInt Y3 = BigIntUtils::mod(R * (U1H2 - X3) - S1 * H3, p_);
    const BigInt Z3 = BigIntUtils::mod(H * P.Z * Q.Z, p_);

    return {X3, Y3, Z3};
}

JacobianPoint EllipticCurve::multiply(BigInt k, const JacobianPoint& P) const {
    k = BigIntUtils::mod(k, q_);
    JacobianPoint R = infinity();

    for (int bitIndex = 255; bitIndex >= 0; --bitIndex) {
        R = doublePoint(R);
        const JacobianPoint added = add(R, P);
        const unsigned bit = static_cast<unsigned>((k >> bitIndex) & 1);
        R = selectPoint(R, added, bit);
    }

    return R;
}

JacobianPoint EllipticCurve::selectPoint(const JacobianPoint& A,
                                         const JacobianPoint& B,
                                         unsigned bit) const {
    const BigInt chooseB = bit;
    const BigInt chooseA = 1 - chooseB;

    return {
        BigIntUtils::mod(A.X * chooseA + B.X * chooseB, p_),
        BigIntUtils::mod(A.Y * chooseA + B.Y * chooseB, p_),
        BigIntUtils::mod(A.Z * chooseA + B.Z * chooseB, p_)
    };
}
