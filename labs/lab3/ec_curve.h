#pragma once
#include "number_theory.h"
#include <string>

namespace ecc {

using rsa::BigInt;

struct CurveParams { BigInt p, a, b, q, gx, gy; };

struct Point {
    BigInt x, y;
    bool inf = true; // точка на бесконечности O
};

CurveParams load_secp256k1();
Point point_neg(const Point& P, const CurveParams& c);
Point point_add(const Point& P, const Point& Q, const CurveParams& c);
Point point_double(const Point& P, const CurveParams& c);
Point scalar_mult(const BigInt& k, const Point& P, const CurveParams& c);

BigInt from_hex(const std::string& s);
std::string to_hex(const BigInt& x);
std::array<std::uint8_t, 32> to_bytes32(const BigInt& x);

}