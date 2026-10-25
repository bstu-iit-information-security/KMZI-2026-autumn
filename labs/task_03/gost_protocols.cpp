#include "gost_protocols.hpp"

#include <stdexcept>
#include <string>

GostProtocols::GostProtocols(const EllipticCurve& curve) : curve_(curve) {}

JacobianPoint GostProtocols::publicKey(const BigInt& d) const {
    validateScalar(d, "private key");
    return curve_.multiply(d, curve_.generator());
}

JacobianPoint GostProtocols::ecdhShared(const BigInt& d, const JacobianPoint& otherPublic) const {
    validateScalar(d, "private key");
    return curve_.multiply(d, otherPublic);
}

Signature GostProtocols::signHash(const BigInt& hash, const BigInt& d, const BigInt& k) const {
    validateScalar(d, "private key");
    validateScalar(k, "ephemeral key");

    const BigInt e = BigIntUtils::mod(hash, curve_.q());
    if (e == 0) throw std::runtime_error("Test hash gives e=0");

    const JacobianPoint C = curve_.multiply(k, curve_.generator());
    const AffinePoint Ca = curve_.toAffine(C);
    if (Ca.infinity) throw std::runtime_error("kG is infinity");

    const BigInt r = BigIntUtils::mod(Ca.x, curve_.q());
    if (r == 0) throw std::runtime_error("r=0: choose another k");

    const BigInt s = BigIntUtils::mod(r * d + k * e, curve_.q());
    if (s == 0) throw std::runtime_error("s=0: choose another k");

    return {r, s};
}

bool GostProtocols::verifyHash(const BigInt& hash,
                               const Signature& sig,
                               const JacobianPoint& publicKeyPoint) const {
    if (sig.r <= 0 || sig.r >= curve_.q()) return false;
    if (sig.s <= 0 || sig.s >= curve_.q()) return false;

    const BigInt e = BigIntUtils::mod(hash, curve_.q());
    if (e == 0) return false;

    const BigInt v = BigIntUtils::inverse(e, curve_.q());
    const BigInt z1 = BigIntUtils::mod(sig.s * v, curve_.q());
    const BigInt z2 = BigIntUtils::mod(-sig.r * v, curve_.q());

    const JacobianPoint part1 = curve_.multiply(z1, curve_.generator());
    const JacobianPoint part2 = curve_.multiply(z2, publicKeyPoint);
    const JacobianPoint C = curve_.add(part1, part2);
    const AffinePoint Ca = curve_.toAffine(C);

    if (Ca.infinity) return false;

    const BigInt R = BigIntUtils::mod(Ca.x, curve_.q());
    return R == sig.r;
}

void GostProtocols::validateScalar(const BigInt& x, const char* name) const {
    if (x <= 0 || x >= curve_.q()) {
        throw std::invalid_argument(std::string(name) + " is out of range");
    }
}
