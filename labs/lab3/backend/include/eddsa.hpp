#pragma once
#include "edwards.hpp"
#include "sha512.hpp"
#include <array>
#include <vector>

namespace lab3 {

struct Ed25519KeyPair {
    cpp_int d;
    std::array<uint8_t, 32> hB;
    EdPoint A;
    std::array<uint8_t, 32> publicBytes;
};

struct Ed25519Signature {
    std::array<uint8_t, 32> R;
    cpp_int S;
};

class EdDSA {
public:
    explicit EdDSA(const Ed25519Curve& curve);

    Ed25519KeyPair keygen(const std::array<uint8_t, 32>& seed);

    Ed25519Signature sign(const Ed25519KeyPair& key,
                          const std::vector<uint8_t>& message);

    bool verify(const std::array<uint8_t, 32>& publicKey,
                const std::vector<uint8_t>& message,
                const Ed25519Signature& sig);

    static std::array<uint8_t, 32> compress(const EdPoint& P);

    EdPoint decompress(const std::array<uint8_t, 32>& bytes);

    cpp_int hashToScalar(const std::array<uint8_t, 64>& h);

    cpp_int modQ(const cpp_int& v) const { return v % curve_.q(); }

private:
    const Ed25519Curve& curve_;
};

}