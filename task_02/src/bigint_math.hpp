// ============================================================================
// МОДУЛЬ 1. Теория чисел и арифметика RSA  (вариант 8: N = 3072 бит, SHA-256)
//
// Здесь живёт всё "чистая математика":
//   * расширенный алгоритм Евклида (НОД, обратный элемент);
//   * модульное возведение в степень алгоритмом Joye-Tun
//     (регулярный right-to-left, вариация лестницы Монтгомери) -- ЗАДАЧА ВАРИАНТА 8;
//   * тест простоты Миллера-Рабина и генерация простых чисел.
//
// Библиотека GMP используется ТОЛЬКО как арифметика больших чисел
// (+, -, *, mod). Само возведение в степень, Евклид, Миллер-Рабин -- наши.
// ============================================================================
#pragma once
#include <gmpxx.h>

#include <cstddef>
#include <cstdint>

namespace rsa {

// Криптостойкие случайные байты (/dev/urandom, на Windows -- std::random_device).
void random_bytes(uint8_t* buf, size_t n);

// Случайное число ровно из `bits` бит (старший бит НЕ форсируется).
mpz_class random_bits(unsigned bits);

// Расширенный алгоритм Евклида: g = gcd(a,b) = a*x + b*y.
void ext_gcd(mpz_class& g, mpz_class& x, mpz_class& y,
             const mpz_class& a, const mpz_class& b);

mpz_class gcd(const mpz_class& a, const mpz_class& b);

// inv = a^{-1} mod m. Возвращает false, если обратного нет (gcd != 1).
bool mod_inverse(mpz_class& inv, const mpz_class& a, const mpz_class& m);

// r = base^exp mod mod  -- алгоритм Joye-Tun (Joye's highly regular
// right-to-left exponentiation).
//   exp_bits -- ФИКСИРОВАННОЕ число обрабатываемых бит экспоненты
//   (публичный параметр, например битовая длина модуля), поэтому число
//   итераций не зависит от значения секретной экспоненты.
void powm_joye_tun(mpz_class& r, const mpz_class& base, const mpz_class& exp,
                   const mpz_class& mod, unsigned exp_bits);

// Тест Миллера-Рабина (rounds случайных оснований). true = "вероятно простое".
bool miller_rabin(const mpz_class& n, int rounds);

// Простое число ровно из `bits` бит (два старших бита = 1, чтобы p*q имело
// ровно 2*bits бит) с условием gcd(e, p-1) = 1.
mpz_class gen_prime(unsigned bits, const mpz_class& e);

}  // namespace rsa
