#include "number_theory.h"
#include <random>
#include <stdexcept>

namespace rsa {

namespace {

std::mt19937_64& rng() {
    static std::mt19937_64 gen{std::random_device{}()};
    return gen;
}

BigInt random_bits(int bits) {
    BigInt x = 0;
    for (int i = 0; i < (bits + 63) / 64; ++i)
        x = (x << 64) | BigInt(rng());
    x &= (BigInt(1) << bits) - 1;
    return x;
}

BigInt random_in_range(const BigInt& lo, const BigInt& hi) {
    const BigInt span = hi - lo + 1;
    const int bits = static_cast<int>(boost::multiprecision::msb(span)) + 1;
    while (true) {
        const BigInt r = random_bits(bits);
        if (r < span) return lo + r;
    }
}

}

ExtendedGcd extended_gcd(const BigInt& a, const BigInt& b) {
    BigInt old_r = a, r = b, old_s = 1, s = 0, old_t = 0, t = 1;
    while (r != 0) {
        const BigInt q = old_r / r;
        BigInt tmp = r; r = old_r - q * r; old_r = tmp;
        tmp = s; s = old_s - q * s; old_s = tmp;
        tmp = t; t = old_t - q * t; old_t = tmp;
    }
    if (old_r < 0) { old_r = -old_r; old_s = -old_s; old_t = -old_t; }
    return {old_r, old_s, old_t};
}

BigInt mod_inverse(const BigInt& a, const BigInt& m) {
    const auto [g, x, y] = extended_gcd(a, m);
    if (g != 1) throw std::runtime_error("mod_inverse: ?????????????????? ???????????????? ??????");
    return ((x % m) + m) % m;
}

BigInt mod_pow(const BigInt& base, const BigInt& exp, const BigInt& mod) {
    if (mod == 1) return 0;
    BigInt result = 1 % mod;
    BigInt b = base % mod;
    BigInt e = exp;
    while (e > 0) {
        if ((e & 1) != 0) result = (result * b) % mod;
        b = (b * b) % mod;
        e >>= 1;
    }
    return result;
}

bool is_prime(const BigInt& n, int rounds) {
    if (n < 2) return false;
    for (int p : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}) {
        if (n == p) return true;
        if (n % p == 0) return false;
    }
    BigInt d = n - 1;
    int s = 0;
    while ((d & 1) == 0) { d >>= 1; ++s; }
    for (int i = 0; i < rounds; ++i) {
        const BigInt a = random_in_range(2, n - 2);
        BigInt x = mod_pow(a, d, n);
        if (x == 1 || x == n - 1) continue;
        bool composite = true;
        for (int j = 0; j < s - 1; ++j) {
            x = (x * x) % n;
            if (x == n - 1) { composite = false; break; }
        }
        if (composite) return false;
    }
    return true;
}

BigInt generate_prime(int bits) {
    while (true) {
        BigInt c = random_bits(bits);
        c |= (BigInt(1) << (bits - 1));
        c |= 1;
        if (is_prime(c)) return c;
    }
}

RsaKeys generate_keys(int bits) {
    const int half = bits / 2;
    RsaKeys k;
    k.p = generate_prime(half);
    do { k.q = generate_prime(half); } while (k.p == k.q);
    k.n = k.p * k.q;
    k.e = 65537;
    const BigInt pm = k.p - 1;
    const BigInt qm = k.q - 1;
    const BigInt lambda = (pm / extended_gcd(pm, qm).gcd) * qm;
    if (extended_gcd(k.e, lambda).gcd != 1)
        throw std::runtime_error("generate_keys: gcd(e, lambda) != 1");
    k.d = mod_inverse(k.e, lambda);
    k.dp = k.d % pm;
    k.dq = k.d % qm;
    k.qinv = mod_inverse(k.q % k.p, k.p);
    return k;
}

}
