#include "constant_time.hpp"

namespace ConstantTime {

Bytes32 toBytes32(const BigInt& value, const BigInt& p) {
    Bytes32 out{};
    BigInt tmp = BigIntUtils::mod(value, p);

    for (std::size_t i = 0; i < out.size(); ++i) {
        out[out.size() - 1 - i] = static_cast<std::uint8_t>(tmp & 0xFF);
        tmp >>= 8;
    }

    return out;
}

std::uint8_t equalField(const BigInt& a, const BigInt& b, const BigInt& p) {
    const Bytes32 A = toBytes32(a, p);
    const Bytes32 B = toBytes32(b, p);
    std::uint8_t diff = 0;

    for (std::size_t i = 0; i < A.size(); ++i) {
        diff |= static_cast<std::uint8_t>(A[i] ^ B[i]);
    }

    return static_cast<std::uint8_t>(diff == 0);
}

bool secureCompare(const EllipticCurve& curve,
                   const JacobianPoint& P,
                   const JacobianPoint& Q) {
    const BigInt& p = curve.p();

    const BigInt z1z1 = BigIntUtils::mod(P.Z * P.Z, p);
    const BigInt z2z2 = BigIntUtils::mod(Q.Z * Q.Z, p);
    const BigInt leftX = BigIntUtils::mod(P.X * z2z2, p);
    const BigInt rightX = BigIntUtils::mod(Q.X * z1z1, p);
    const BigInt leftY = BigIntUtils::mod(P.Y * Q.Z * z2z2, p);
    const BigInt rightY = BigIntUtils::mod(Q.Y * P.Z * z1z1, p);

    const std::uint8_t xEqual = equalField(leftX, rightX, p);
    const std::uint8_t yEqual = equalField(leftY, rightY, p);
    const std::uint8_t pInf = equalField(P.Z, BigInt(0), p);
    const std::uint8_t qInf = equalField(Q.Z, BigInt(0), p);
    const std::uint8_t bothInf = static_cast<std::uint8_t>(pInf & qInf);
    const std::uint8_t bothFinite = static_cast<std::uint8_t>((1U ^ pInf) & (1U ^ qInf));
    const std::uint8_t finiteEqual = static_cast<std::uint8_t>(xEqual & yEqual);
    const std::uint8_t result = static_cast<std::uint8_t>(bothInf | (bothFinite & finiteEqual));

    return result != 0;
}

}
