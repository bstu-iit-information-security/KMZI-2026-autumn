// МОДУЛЬ 2. Вычислительное ядро RSA с CRT (алгоритм Гарнера).
// Индивидуальная задача варианта 3: constant-time Гарнер, без ветвления if (m1 < m2).
#pragma once
#include "numtheory.hpp"
#include "config.hpp"
#include <cstdint>

namespace rsa {

// Преобразования фиксированной длины (без динамических контейнеров)
void to_limbs(const BigInt& x, uint64_t* out, size_t nlimbs);        // little-endian лимбы, дополнение нулями
void from_limbs(BigInt& x, const uint64_t* in, size_t nlimbs);
void int_to_bytes(const BigInt& x, uint8_t* out, size_t len);        // big-endian, ровно len байт (len кратно 8)
void bytes_to_int(BigInt& x, const uint8_t* in, size_t len);

// c = m^e mod N, 0 <= m < N (публичная операция)
void encrypt_raw(BigInt& c, const BigInt& m, const PublicKey& pub);
// m = c^d mod N без CRT (для сравнения и тестов)
void decrypt_plain(BigInt& m, const BigInt& c, const PrivateKey& prv);

// ---- Шаг Гарнера: diff = (m1 - m2) mod p, diff in [0, p) ----
// constant-time: фиксированные P_LIMBS лимбов, mpn_sub_n/mpn_add_n и маска вместо if (m1 < m2).
// Требование: m1 < p, m2 < 2p (выполнено, т.к. p и q имеют по 1536 бит с двумя единичными старшими битами).
void garner_diff_ct(BigInt& diff, const BigInt& m1, const BigInt& m2, const BigInt& p);
// эталон из методички с ветвлением (для сравнения и измерения утечки)
void garner_diff_naive(BigInt& diff, const BigInt& m1, const BigInt& m2, const BigInt& p);

// m = m2 + q * (q_inv * (m1 - m2) mod p)
void garner_combine_ct(BigInt& m, const BigInt& m1, const BigInt& m2,
                       const BigInt& p, const BigInt& q, const BigInt& qinv);
void garner_combine_naive(BigInt& m, const BigInt& m1, const BigInt& m2,
                          const BigInt& p, const BigInt& q, const BigInt& qinv);

// m = c^d mod N через CRT: m1 = c^dp mod p, m2 = c^dq mod q, затем constant-time Гарнер
void decrypt_crt(BigInt& m, const BigInt& c, const PrivateKey& prv);

} // namespace rsa
