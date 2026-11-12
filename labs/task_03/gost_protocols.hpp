#pragma once

#include "elliptic_curve.hpp"

struct Signature {
    BigInt r;
    BigInt s;
};

class GostProtocols {
public:
    explicit GostProtocols(const EllipticCurve& curve);

    BigInt generatePrivateKey() const;
    BigInt hashMessage(const std::string& messageHex) const;
    JacobianPoint publicKey(const BigInt& d) const;
    JacobianPoint ecdhShared(const BigInt& d, const JacobianPoint& otherPublic) const;
    Signature signMessage(const std::string& messageHex, const BigInt& d) const;
    bool verifyMessage(const std::string& messageHex,
                       const Signature& sig,
                       const JacobianPoint& publicKeyPoint) const;

private:
    BigInt randomScalar() const;
    void validateScalar(const BigInt& x, const char* name) const;

    const EllipticCurve& curve_;
};
