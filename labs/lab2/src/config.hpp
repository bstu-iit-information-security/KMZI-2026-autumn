// Параметры варианта 3: N = 3072 бит, хеш SHA-512,
// задача оптимизации: constant-time алгоритм Гарнера в CRT (без ветвления if (m1 < m2)).
#pragma once
#include <cstddef>
#include <cstdint>

namespace cfg {
constexpr size_t   RSA_BITS   = 3072;
constexpr size_t   K          = RSA_BITS / 8;          // 384 байта - длина модуля
constexpr size_t   HLEN       = 64;                    // SHA-512
constexpr size_t   DB_LEN     = K - HLEN - 1;          // 319
constexpr size_t   MAX_MSG    = K - 2 * HLEN - 2;      // 254
constexpr size_t   PRIME_BITS = RSA_BITS / 2;          // 1536
constexpr size_t   P_LIMBS    = PRIME_BITS / 64;       // 24 лимба фиксированно
constexpr size_t   N_LIMBS    = RSA_BITS / 64;         // 48 лимбов
constexpr uint32_t E_PUB      = 65537;
constexpr int      MR_ROUNDS  = 40;
}
