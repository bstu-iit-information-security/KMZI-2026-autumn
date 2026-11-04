#ifndef CRYPTO_PROTOCOLS_H
#define CRYPTO_PROTOCOLS_H

#include "Curves.h"
#include <stdexcept>

class CryptoProtocols {
public:
    using u64 = Curves::u64;
    using Point = Curves::Point;

    struct KeyPair {
        u64   d;
        Point Q;
    };

    struct Signature {
        u64 r;
        u64 s;
    };

    explicit CryptoProtocols(const Curves& curve);

    KeyPair generateKeyPair() const;

    Signature sign(u64 d_priv, const Point& Q_pub, u64 hash_e) const;

    bool verify(const Point& Q_pub, u64 hash_e, const Signature& sig) const;

    u64 ecdhSharedSecret(u64 d_priv, const Point& Q_peer) const;

    bool isValidPrivateKey(u64 d) const;

private:
    const Curves& curve_;

    u64 randomScalar() const;

    static u64 mulmodQ(u64 a, u64 b, u64 q);
    static u64 addmodQ(u64 a, u64 b, u64 q);
    static u64 submodQ(u64 a, u64 b, u64 q);
    static u64 modInverseQ(u64 a, u64 q);
};

#endif

