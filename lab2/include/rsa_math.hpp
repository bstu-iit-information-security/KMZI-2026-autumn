#pragma once

#include <openssl/bn.h>

#include <cstdint>
#include <string>

// Обёртка над BIGNUM. Библиотека больших чисел используется только как
// арифметика (сложение, умножение, деление, остаток). НОД, обратный элемент,
// модульная экспонента и тест Миллера–Рабина реализованы в этом модуле.
class Bn {
public:
    Bn();
    ~Bn();
    Bn(const Bn& other);
    Bn& operator=(const Bn& other);
    Bn(Bn&& other) noexcept;
    Bn& operator=(Bn&& other) noexcept;

    BIGNUM* raw() { return v_; }
    const BIGNUM* raw() const { return v_; }

private:
    BIGNUM* v_;
};

struct RsaPrivateKey {
    Bn n;
    Bn e;
    Bn d;
    Bn p;
    Bn q;
    Bn dp;
    Bn dq;
    Bn qinv;
};

// Модуль 1. Теория чисел и арифметика RSA.
// Вариант 11: constant-time тест Миллера–Рабина без ранних выходов из цикла.
class RsaMath {
public:
    static constexpr int kModulusBits = 3072;
    static constexpr int kPrimeBits = kModulusBits / 2;
    static constexpr unsigned long kPublicExponent = 65537UL;
    // FIPS 186-4 для случайных 1536-битных простых допускает 3–4 раунда.
    // Здесь 5: оценка ошибки для злонамеренного составного числа ≤ 4^{-5}.
    static constexpr int kMrRounds = 5;
    // Фиксированное число возведений в квадрат. s = v2(n-1) почти всегда
    // меньше этого порога (P(s > 128) = 2^{-128}); цикл не зависит от s.
    static constexpr int kFixedSquarings = 128;

    static bool mod_exp(Bn& out, const Bn& base, const Bn& exp, const Bn& mod);
    static bool mod_inverse(Bn& out, const Bn& a, const Bn& mod);
    static bool extended_gcd(Bn& gcd, Bn& x, Bn& y, const Bn& a, const Bn& b);

    // Одинаковый набор свидетелей для честного сравнения CT и VT.
    static bool miller_rabin_ct(const Bn& n, const Bn* bases, int n_bases);
    static bool miller_rabin_vt(const Bn& n, const Bn* bases, int n_bases);
    static bool random_bases(Bn* bases, int n_bases, const Bn& n);
    static bool miller_rabin_ct_random(const Bn& n, int rounds);

    static bool generate_prime(Bn& prime, int bits, unsigned long exponent);
    static bool generate_keypair(RsaPrivateKey& key, int modulus_bits = kModulusBits);
    // Заполняет n, d, dp, dq, qinv по уже заданным p, q, e.
    static bool derive_private(RsaPrivateKey& key);

    static std::string hex(const Bn& v);
    static bool from_hex(Bn& v, const char* hex);
    static bool from_word(Bn& v, unsigned long w);
    static bool from_bytes(Bn& v, const uint8_t* in, int len);
    static bool to_bytes_pad(const Bn& v, uint8_t* out, int len);
    static int bit_length(const Bn& v);
};
