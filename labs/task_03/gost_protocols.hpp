#pragma once

#include "elliptic_curve.hpp"

struct Signature {
    BigInt r;
    BigInt s;
};

class GostProtocols {
public:
    explicit GostProtocols(const EllipticCurve& curve);

    JacobianPoint publicKey(const BigInt& d) const;
    JacobianPoint ecdhShared(const BigInt& d, const JacobianPoint& otherPublic) const;
    Signature signHash(const BigInt& hash, const BigInt& d, const BigInt& k) const;
    bool verifyHash(const BigInt& hash,
                    const Signature& sig,
                    const JacobianPoint& publicKeyPoint) const;

private:
    void validateScalar(const BigInt& x, const char* name) const;

    const EllipticCurve& curve_;
};
