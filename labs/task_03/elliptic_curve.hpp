#pragma once

#include <boost/multiprecision/cpp_int.hpp>
#include <cstddef>
#include <string>

using BigInt = boost::multiprecision::cpp_int;

namespace BigIntUtils {
unsigned hexDigit(char c);
BigInt fromHex(const std::string& hex);
BigInt mod(const BigInt& x, const BigInt& m);
BigInt inverse(const BigInt& a, const BigInt& m);
std::string toFixedHex(BigInt value, std::size_t bytes);
}

struct JacobianPoint {
    BigInt X;
    BigInt Y;
    BigInt Z;
};

struct AffinePoint {
    BigInt x;
    BigInt y;
    bool infinity;
};

class EllipticCurve {
public:
    static constexpr std::size_t FIELD_BYTES = 32;

    EllipticCurve(const std::string& pHex,
                  const std::string& aHex,
                  const std::string& bHex,
                  const std::string& qHex,
                  const std::string& gxHex,
                  const std::string& gyHex);

    const BigInt& p() const;
    const BigInt& q() const;
    const JacobianPoint& generator() const;

    JacobianPoint infinity() const;
    bool isInfinity(const JacobianPoint& P) const;
    JacobianPoint fromAffine(const BigInt& x, const BigInt& y) const;
    AffinePoint toAffine(const JacobianPoint& P) const;
    bool isOnCurveAffine(const AffinePoint& P) const;
    JacobianPoint doublePoint(const JacobianPoint& P) const;
    JacobianPoint add(const JacobianPoint& P, const JacobianPoint& Q) const;
    JacobianPoint multiply(BigInt k, const JacobianPoint& P) const;

private:
    JacobianPoint selectPoint(const JacobianPoint& A,
                              const JacobianPoint& B,
                              unsigned bit) const;

    BigInt p_;
    BigInt a_;
    BigInt b_;
    BigInt q_;
    JacobianPoint G_;
};
