#pragma once

#include "elliptic_curve.hpp"

#include <array>
#include <cstdint>

namespace ConstantTime {

using Bytes32 = std::array<std::uint8_t, EllipticCurve::FIELD_BYTES>;

Bytes32 toBytes32(const BigInt& value, const BigInt& p);
std::uint8_t equalField(const BigInt& a, const BigInt& b, const BigInt& p);
bool secureCompare(const EllipticCurve& curve,
                   const JacobianPoint& P,
                   const JacobianPoint& Q);

}
