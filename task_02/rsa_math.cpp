#include "rsa_math.hpp"
#include "rng.hpp"
#include <stdexcept>
#include <vector>

BigInt ext_gcd(const BigInt& a, const BigInt& b, BigInt& x, BigInt& y)
{
    BigInt old_r = a;
    BigInt r = b;
    BigInt old_s(1);
    BigInt s(0);
    BigInt old_t(0);
    BigInt t(1);
    while (!r.is_zero()) {
        BigInt q = old_r / r;
        BigInt next_r = old_r - q * r;
        old_r = r;
        r = next_r;
        BigInt next_s = old_s - q * s;
        old_s = s;
        s = next_s;
        BigInt next_t = old_t - q * t;
        old_t = t;
        t = next_t;
    }
    x = old_s;
    y = old_t;
    return old_r;
}

BigInt gcd(const BigInt& a, const BigInt& b)
{
    BigInt x;
    BigInt y;
    return ext_gcd(a, b, x, y);
}

BigInt lcm(const BigInt& a, const BigInt& b)
{
    return (a / gcd(a, b)) * b;
}

BigInt mod_inverse(const BigInt& a, const BigInt& m)
{
    BigInt x;
    BigInt y;
    BigInt g = ext_gcd(a % m, m, x, y);
    if (g != BigInt(1)) {
        throw std::invalid_argument("modular inverse does not exist");
    }
    return x % m;
}

BigInt mod_pow(const BigInt& base, const BigInt& exponent, const BigInt& modulus)
{
    if (modulus.is_zero()) {
        throw std::invalid_argument("zero modulus");
    }
    BigInt result = BigInt(1) % modulus;
    BigInt b = base % modulus;
    size_t bits = exponent.bit_length();
    for (size_t i = bits; i > 0; i--) {
        result = (result * result) % modulus;
        if (exponent.test_bit(i - 1)) {
            result = (result * b) % modulus;
        }
    }
    return result;
}

static const std::vector<unsigned long>& small_primes()
{
    static std::vector<unsigned long> primes;
    if (primes.empty()) {
        for (unsigned long c = 2; c < 2000; c++) {
            bool prime = true;
            for (unsigned long d = 2; d * d <= c; d++) {
                if (c % d == 0) {
                    prime = false;
                    break;
                }
            }
            if (prime) {
                primes.push_back(c);
            }
        }
    }
    return primes;
}

static BigInt random_in_range(const BigInt& low, const BigInt& high)
{
    size_t bytes = (high.bit_length() + 7) / 8 + 8;
    std::vector<uint8_t> buf(bytes);
    random_bytes(buf.data(), bytes);
    BigInt r = BigInt::from_bytes(buf.data(), bytes);
    return low + (r % (high - low + BigInt(1)));
}

bool is_probable_prime(const BigInt& n, int rounds)
{
    if (n < BigInt(2)) {
        return false;
    }
    const std::vector<unsigned long>& primes = small_primes();
    for (size_t i = 0; i < primes.size(); i++) {
        if (n == BigInt(primes[i])) {
            return true;
        }
        if (n.mod_ulong(primes[i]) == 0) {
            return false;
        }
    }
    BigInt n_minus_1 = n - BigInt(1);
    size_t s = 0;
    while (!n_minus_1.test_bit(s)) {
        s++;
    }
    BigInt d = n_minus_1 / BigInt(1).shifted_left(s);
    for (int round = 0; round < rounds; round++) {
        BigInt a = random_in_range(BigInt(2), n - BigInt(2));
        BigInt x = mod_pow(a, d, n);
        if (x == BigInt(1) || x == n_minus_1) {
            continue;
        }
        bool composite = true;
        for (size_t r = 1; r < s; r++) {
            x = (x * x) % n;
            if (x == n_minus_1) {
                composite = false;
                break;
            }
        }
        if (composite) {
            return false;
        }
    }
    return true;
}

BigInt generate_prime(size_t bits)
{
    if (bits < 16) {
        throw std::invalid_argument("prime size is too small");
    }
    size_t bytes = (bits + 7) / 8;
    size_t excess = bytes * 8 - bits;
    std::vector<uint8_t> buf(bytes);
    for (;;) {
        random_bytes(buf.data(), bytes);
        buf[0] = static_cast<uint8_t>(buf[0] & (0xFFu >> excess));
        BigInt candidate = BigInt::from_bytes(buf.data(), bytes);
        candidate.set_bit(bits - 1);
        candidate.set_bit(bits - 2);
        candidate.set_bit(0);
        if (is_probable_prime(candidate, 40)) {
            return candidate;
        }
    }
}

KeyPair generate_keypair(size_t modulus_bits, unsigned long public_exponent)
{
    if (modulus_bits < 64 || modulus_bits % 2 != 0) {
        throw std::invalid_argument("invalid modulus size");
    }
    BigInt e(public_exponent);
    size_t half = modulus_bits / 2;
    for (;;) {
        BigInt p = generate_prime(half);
        BigInt q = generate_prime(half);
        if (p == q) {
            continue;
        }
        if (p < q) {
            BigInt tmp = p;
            p = q;
            q = tmp;
        }
        BigInt n = p * q;
        if (n.bit_length() != modulus_bits) {
            continue;
        }
        BigInt lambda = lcm(p - BigInt(1), q - BigInt(1));
        if (gcd(e, lambda) != BigInt(1)) {
            continue;
        }
        BigInt d = mod_inverse(e, lambda);
        if (d.bit_length() <= half) {
            continue;
        }
        KeyPair kp;
        kp.pub.n = n;
        kp.pub.e = e;
        kp.priv.n = n;
        kp.priv.d = d;
        kp.priv.p = p;
        kp.priv.q = q;
        kp.priv.dp = d % (p - BigInt(1));
        kp.priv.dq = d % (q - BigInt(1));
        kp.priv.qinv = mod_inverse(q, p);
        return kp;
    }
}
