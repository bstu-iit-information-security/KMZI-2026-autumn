#pragma once
#include "bigint.h"
#include "sha512.h"
#include <random>
#include <stdexcept>
#include <cstring>

constexpr size_t RSA_KEY_BYTES = 384; // 3072 бита

struct RSAKeyPair {
    BigInt N, e, d, p, q, dp, dq, qinv;
};

// === ИСПРАВЛЕНО: тест Миллера-Рабина ===
inline bool miller_rabin(const BigInt& n, unsigned rounds, std::mt19937_64& rng) {
    if (n < BigInt(2)) return false;
    if (n == BigInt(2) || n == BigInt(3)) return true;
    if (!n.is_odd()) return false;

    // n - 1 = 2^r * d, d нечётно
    BigInt n_minus_1 = n - BigInt(1);
    unsigned r = 0;
    BigInt d = n_minus_1;
    while (!d.is_odd()) { d = d >> 1; r++; }

    for (unsigned i = 0; i < rounds; ++i) {
        // a ∈ [2, n-2]
        BigInt a = BigInt::random_bits(n.bit_length() - 1, rng) % (n - BigInt(3)) + BigInt(2);
        BigInt x = BigInt::mod_pow(a, d, n);
        if (x == BigInt(1) || x == n_minus_1) continue;
        bool composite = true;
        for (unsigned j = 0; j < r - 1; ++j) {
            x = (x * x) % n;
            if (x == n_minus_1) { composite = false; break; }
        }
        if (composite) return false;
    }
    return true;
}

inline BigInt generate_prime(unsigned bits, std::mt19937_64& rng) {
    while (true) {
        BigInt candidate = BigInt::random_bits(bits, rng);
        if (miller_rabin(candidate, 40, rng)) return candidate;
    }
}

// === ИСПРАВЛЕНО: настоящая генерация 3072-битных ключей ===
inline RSAKeyPair generate_keys(std::mt19937_64& rng) {
    RSAKeyPair key;
    // p, q — простые по 1536 бит каждое, N = p*q ≈ 3072 бита
    key.p = generate_prime(1536, rng);
    do {
        key.q = generate_prime(1536, rng);
    } while (key.q == key.p);

    key.e = BigInt(65537);
    key.N = key.p * key.q;

    BigInt p1 = key.p - BigInt(1);
    BigInt q1 = key.q - BigInt(1);
    BigInt phi = p1 * q1;

    key.d = BigInt::mod_inverse(key.e, phi);
    key.dp = key.d % p1;
    key.dq = key.d % q1;
    key.qinv = BigInt::mod_inverse(key.q % key.p, key.p);
    return key;
}

inline void rsa_encrypt_raw(const uint8_t* in, size_t in_len, uint8_t* out, const RSAKeyPair& key) {
    BigInt m = BigInt::from_bytes(in, in_len);
    BigInt c = BigInt::mod_pow(m, key.e, key.N);
    std::vector<uint8_t> bytes = c.to_bytes(RSA_KEY_BYTES);
    std::memcpy(out, bytes.data(), RSA_KEY_BYTES);
}

// === ИСПРАВЛЕНО: constant-time CRT-Гарнер + приведение по модулю N ===
inline void rsa_decrypt_crt_constant_time(const uint8_t* in, uint8_t* out, const RSAKeyPair& key) {
    BigInt c = BigInt::from_bytes(in, RSA_KEY_BYTES);

    BigInt m1 = BigInt::mod_pow(c, key.dp, key.p);
    BigInt m2 = BigInt::mod_pow(c, key.dq, key.q);

    BigInt m2_mod_p = m2 % key.p;
    // constant-time (m1 - m2) mod p: прибавляем p всегда, потом % p
    BigInt diff = (m1 + key.p - m2_mod_p) % key.p;
    BigInt h = (key.qinv * diff) % key.p;

    // ВАЖНО: приводим результат по модулю N, чтобы m < N
    BigInt m = (m2 + h * key.q) % key.N;

    std::vector<uint8_t> bytes = m.to_bytes(RSA_KEY_BYTES);
    std::memcpy(out, bytes.data(), RSA_KEY_BYTES);
}