// МОДУЛЬ 3. OAEP (PKCS#1 v2.1, MGF1-SHA-512) и constant-time деинкапсуляция.
// Все буферы - статические массивы фиксированного размера (K=384, DB=319), без std::vector и вложенных контейнеров.
#pragma once
#include "rsa_core.hpp"
#include <cstddef>
#include <cstdint>

namespace oaep {
using namespace cfg;

// MGF1(Z, L): Hash(Z || C) для C = 0,1,2,... (4 байта big-endian). Длины публичны.
void mgf1(const uint8_t* z, size_t zlen, uint8_t* out, size_t outlen);

// EM = 0x00 || maskedSeed || maskedDB. seed (HLEN байт) передается снаружи, чтобы кодирование было тестируемым.
// false, если mlen > MAX_MSG (длина сообщения публична).
bool encode(const uint8_t* msg, size_t mlen, const uint8_t* label, size_t llen,
            const uint8_t seed[HLEN], uint8_t em[K]);

// Constant-time деинкапсуляция: нет return/break/if в зависимости от секретных байтов EM.
// Возвращает 1 (успех) или 0 (любая ошибка) - единственное ветвление на публичном итоге, после всех вычислений.
// out всегда заполняется полностью (MAX_MSG байт), *outlen = 0 при ошибке.
uint32_t decode(const uint8_t em[K], const uint8_t* label, size_t llen,
                uint8_t out[MAX_MSG], size_t* outlen);

// Полный цикл: OAEP + сырой RSA
bool encrypt(const PublicKey& pub, const uint8_t* msg, size_t mlen,
             const uint8_t* label, size_t llen, uint8_t ct[K]);
bool decrypt(const PrivateKey& prv, const uint8_t ct[K],
             const uint8_t* label, size_t llen, uint8_t out[MAX_MSG], size_t* outlen);

} // namespace oaep
