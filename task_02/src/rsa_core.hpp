// ============================================================================
// МОДУЛЬ 2. Вычислительное ядро RSA с CRT (вариант 8: N = 3072 бит)
//
//   c = m^e mod N                       (шифрование, "сырой" RSA)
//   m = c^d mod N  через CRT/Гарнер     (расшифрование, ~в 4 раза быстрее)
//
// Все возведения в степень идут через powm_joye_tun (модуль 1).
// ============================================================================
#pragma once
#include <gmpxx.h>

namespace rsa {

constexpr unsigned MODULUS_BITS = 3072;  // вариант 8

struct PublicKey {
    mpz_class n, e;
};

struct PrivateKey {
    mpz_class n, e;
    mpz_class d;          // секретная экспонента
    mpz_class p, q;       // простые множители
    mpz_class dp, dq;     // d mod (p-1), d mod (q-1)
    mpz_class qinv;       // q^{-1} mod p
};

// Генерация ключей: p, q по bits/2 бит, e = 65537, d = e^{-1} mod lambda(N),
// предвычисление dp, dq, qinv.
void generate_keypair(PublicKey& pub, PrivateKey& priv, unsigned bits = MODULUS_BITS);

// c = m^e mod N, требуется 0 <= m < N
void rsa_encrypt_raw(mpz_class& c, const mpz_class& m, const PublicKey& pub);

// m = c^d mod N по алгоритму Гарнера (CRT)
void rsa_decrypt_crt(mpz_class& m, const mpz_class& c, const PrivateKey& priv);

// То же без CRT (только для сравнения скорости в отчёте)
void rsa_decrypt_plain(mpz_class& m, const mpz_class& c, const PrivateKey& priv);

}  // namespace rsa
