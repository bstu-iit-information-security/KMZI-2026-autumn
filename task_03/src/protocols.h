#ifndef PROTOCOLS_H
#define PROTOCOLS_H

// Модуль 2. SHA-512, ECDH на кривой Эдвардса и подпись EdDSA (Ed25519, RFC 8032).

#include <cstdint>
#include <cstddef>
#include "ec_algebra.h"

// ---- SHA-512 (собственная реализация) ----
struct Sha512 {
    uint64_t h[8];
    uint8_t buf[128];
    uint64_t totalLen;
    size_t bufLen;
};
void sha512Init(Sha512* s);
void sha512Update(Sha512* s, const uint8_t* data, size_t len);
void sha512Final(Sha512* s, uint8_t out[64]);
void sha512(const uint8_t* data, size_t len, uint8_t out[64]);

// ---- ключи ----
struct KeyPair {
    uint8_t seed[32];       // секретное начальное значение
    uint8_t scalar[32];     // секретный скаляр a (после clamping), little-endian
    uint8_t prefix[32];     // вторая половина SHA-512(seed)
    uint8_t publicKey[32];  // A = a*G (сжатое представление)
};
void eddsaKeyFromSeed(const uint8_t seed[32], KeyPair* kp);

// ---- ЭЦП ----
void eddsaSign(const KeyPair& kp, const uint8_t* msg, size_t msgLen, uint8_t sig[64]);
bool eddsaVerify(const uint8_t publicKey[32], const uint8_t* msg, size_t msgLen, const uint8_t sig[64]);

// ---- ECDH ----
// Закрытый скаляр - clamped SHA-512(seed) (кофактор 8 убирается очисткой трёх младших бит).
bool ecdhSharedSecret(const uint8_t scalar[32], const uint8_t peerPublic[32], uint8_t shared[32]);

#endif
