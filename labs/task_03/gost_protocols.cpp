
#include "gost_protocols.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

GostProtocols::GostProtocols(const EllipticCurve& curve) : curve_(curve) {}

BigInt GostProtocols::randomScalar() const {
    const BigInt& q = curve_.q();
    if (q <= 1) throw std::invalid_argument("Invalid group order");

    std::array<unsigned char, EllipticCurve::FIELD_BYTES> bytes{};

    for (;;) {
        if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }

        BigInt value = 0;
        for (unsigned char byte : bytes) {
            value <<= 8;
            value += byte;
        }

        if (value > 0 && value < q) return value;
    }
}

BigInt GostProtocols::generatePrivateKey() const {
    return randomScalar();
}

BigInt GostProtocols::hashMessage(const std::string& messageHex) const {
    if (messageHex.size() % 2 != 0) {
        throw std::invalid_argument("Message must contain whole hex bytes");
    }

    std::vector<unsigned char> message;
    message.reserve(messageHex.size() / 2);

    for (std::size_t i = 0; i < messageHex.size(); i += 2) {
        const unsigned hi = BigIntUtils::hexDigit(messageHex[i]);
        const unsigned lo = BigIntUtils::hexDigit(messageHex[i + 1]);
        message.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }

    using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    DigestContext context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!context) throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    if (EVP_DigestUpdate(context.get(), message.data(), message.size()) != 1) {
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned digestSize = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digestSize) != 1) {
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    BigInt hash = 0;
    for (unsigned i = 0; i < digestSize; ++i) {
        hash <<= 8;
        hash += digest[i];
    }
    return hash;
}

JacobianPoint GostProtocols::publicKey(const BigInt& d) const {
    validateScalar(d, "private key");
    return curve_.multiply(d, curve_.generator());
}

JacobianPoint GostProtocols::ecdhShared(const BigInt& d, const JacobianPoint& otherPublic) const {
    validateScalar(d, "private key");
    if (curve_.isInfinity(otherPublic) || !curve_.isOnCurveAffine(curve_.toAffine(otherPublic))) {
        throw std::invalid_argument("Invalid peer public key");
    }
    return curve_.multiply(d, otherPublic);
}

Signature GostProtocols::signMessage(const std::string& messageHex, const BigInt& d) const {
    validateScalar(d, "private key");
    BigInt e = BigIntUtils::mod(hashMessage(messageHex), curve_.q());
    if (e == 0) e = 1;

    for (;;) {
        const BigInt k = randomScalar();
        const JacobianPoint C = curve_.multiply(k, curve_.generator());
        const AffinePoint Ca = curve_.toAffine(C);
        if (Ca.infinity) continue;

        const BigInt r = BigIntUtils::mod(Ca.x, curve_.q());
        if (r == 0) continue;

        const BigInt s = BigIntUtils::mod(r * d + k * e, curve_.q());
        if (s == 0) continue;

        return {r, s};
    }
}

bool GostProtocols::verifyMessage(const std::string& messageHex,
                                  const Signature& sig,
                                  const JacobianPoint& publicKeyPoint) const {
    if (sig.r <= 0 || sig.r >= curve_.q()) return false;
    if (sig.s <= 0 || sig.s >= curve_.q()) return false;
    if (curve_.isInfinity(publicKeyPoint) ||
        !curve_.isOnCurveAffine(curve_.toAffine(publicKeyPoint))) return false;

    BigInt e = BigIntUtils::mod(hashMessage(messageHex), curve_.q());
    if (e == 0) e = 1;

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
