#pragma once
#include "ec_curve.h"

namespace ecc {

struct KeyPair { BigInt d; Point Q; };
struct Signature { BigInt r, s; };

BigInt generate_nonce(const CurveParams& c);
KeyPair keygen(const CurveParams& c);
BigInt ecdh_shared(const BigInt& d, const Point& Q_other, const CurveParams& c);

Signature ecdsa_sign(const BigInt& e, const BigInt& d, const BigInt& k, const CurveParams& c);
bool ecdsa_verify(const BigInt& e, const Signature& sig, const Point& Q, const CurveParams& c);

}