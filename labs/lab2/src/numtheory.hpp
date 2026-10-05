// МОДУЛЬ 1. Теория чисел и арифметика RSA.
// GMP используется только как арифметика больших чисел (+, -, *, mod, powm).
// Расширенный алгоритм Евклида, тест Миллера-Рабина, поиск простых и генерация ключей написаны здесь.
#pragma once
#include <gmp.h>
#include <cstddef>
#include <cstdint>

// RAII-обертка над mpz_t. Перед освобождением затирает лимбы (секреты не остаются в куче).
class BigInt {
public:
    BigInt()                       { mpz_init(v_); }
    explicit BigInt(unsigned long x) { mpz_init_set_ui(v_, x); }
    BigInt(const BigInt& o)        { mpz_init_set(v_, o.v_); }
    BigInt& operator=(const BigInt& o) { if (this != &o) mpz_set(v_, o.v_); return *this; }
    ~BigInt();
    mpz_ptr    get()       { return v_; }
    mpz_srcptr get() const { return v_; }
    size_t bits() const    { return mpz_sizeinbase(v_, 2); }
private:
    mpz_t v_;
};

struct PublicKey  { BigInt n, e; };
struct PrivateKey { BigInt n, e, d, p, q, dp, dq, qinv; };   // d, p, q, dp, dq, qinv - секретны

namespace nt {

// g = gcd(a,b) = a*x + b*y  (a, b >= 0)
void ext_gcd(BigInt& g, BigInt& x, BigInt& y, const BigInt& a, const BigInt& b);
// r = a^{-1} mod m; false, если gcd(a,m) != 1
bool mod_inverse(BigInt& r, const BigInt& a, const BigInt& m);
// r = base^exp mod m. secret=true -> mpz_powm_sec (без зависимости от значений экспоненты; нужен нечетный m)
void mod_pow(BigInt& r, const BigInt& base, const BigInt& exp, const BigInt& m, bool secret);

// r = случайное число ровно из `bits` бит (если top2, два старших бита = 1, чтобы p*q имело ровно 2*bits бит)
void random_bits(BigInt& r, size_t bits, bool top2);
bool miller_rabin(const BigInt& n, int rounds);
void gen_prime(BigInt& p, size_t bits, uint32_t e);

void generate_keypair(PublicKey& pub, PrivateKey& prv, size_t bits, uint32_t e = 65537);

} // namespace nt
