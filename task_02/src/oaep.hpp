// ============================================================================
// МОДУЛЬ 3. Схема паддинга OAEP (PKCS#1 v2.1) + constant-time защита
//           Вариант 8: N = 3072 бит (k = 384 байта), хеш SHA-256 (hLen = 32)
//
// Модуль НЕ знает про большие числа: он превращает сообщение в байтовый блок EM
// длины k (и обратно). Все буферы -- статические массивы фиксированного
// размера (никаких vector / вложенных контейнеров).
// ============================================================================
#pragma once
#include <cstddef>
#include <cstdint>

namespace oaep {

constexpr size_t K = 384;                 // длина модуля N в байтах (3072 бит)
constexpr size_t HLEN = 32;               // SHA-256
constexpr size_t DBLEN = K - HLEN - 1;    // длина блока данных DB = 351
constexpr size_t MAX_MSG = K - 2 * HLEN - 2;  // 318 байт -- максимум для M

// MGF1 на базе SHA-256: mask[0..mask_len) = H(Z||0) || H(Z||1) || ...
void mgf1_sha256(const uint8_t* z, size_t z_len, uint8_t* mask, size_t mask_len);

// Упаковка. seed -- ровно HLEN байт случайности (передаётся снаружи, чтобы
// можно было тестировать детерминированно).
// Возврат: 0 -- успех, -1 -- сообщение длиннее MAX_MSG.
int encode_with_seed(uint8_t em[K], const uint8_t* msg, size_t msg_len,
                     const uint8_t* label, size_t label_len,
                     const uint8_t seed[HLEN]);

// То же со случайным seed из /dev/urandom.
int encode(uint8_t em[K], const uint8_t* msg, size_t msg_len,
           const uint8_t* label, size_t label_len);

// Распаковка в режиме constant-time: БЕЗ раннего выхода.
// out -- буфер минимум MAX_MSG байт. *out_len -- длина сообщения.
// Возврат: 0 -- EM корректен, -1 -- любая ошибка (всегда одно и то же значение).
int decode(uint8_t* out, size_t* out_len, const uint8_t em[K],
           const uint8_t* label, size_t label_len);

}  // namespace oaep
