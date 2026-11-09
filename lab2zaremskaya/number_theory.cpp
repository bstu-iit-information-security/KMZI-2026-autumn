#include "number_theory.hpp"

#include <fstream>
#include <stdexcept>

#if defined(_WIN32)
  #include <windows.h>
  #include <bcrypt.h>
#else
  #include <openssl/rand.h>
#endif

namespace rsa {
namespace {

const unsigned kSmallPrimes[] = {
    3,   5,   7,   11,  13,  17,  19,  23,  29,  31,  37,  41,  43,  47,  53,  59,  61,  67,  71,
    73,  79,  83,  89,  97,  101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
    173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
    277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389,
    397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631,
    641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757,
    761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883,
    887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997};

bool trial_division(const BigInt& n) {
    for (unsigned p : kSmallPrimes) {
        BigInt pr(p);
        if (n.cmp(pr) == 0) {
            return true;
        }
        if (n.mod(pr).is_zero()) {
            return false;
        }
    }
    return true;
}

}  // namespace

bool random_bytes(uint8_t* buf, std::size_t n) {
#if defined(_WIN32)

    NTSTATUS st = BCryptGenRandom(nullptr, buf, static_cast<ULONG>(n),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st == 0;  
#else

#endif
}

BigInt gcd(const BigInt& a, const BigInt& b) {
    BigInt x = a;
    BigInt y = b;
    while (!y.is_zero()) {
        BigInt t = y;
        y = x.mod(y);
        x = t;
    }
    return x;
}

void egcd(const BigInt& a, const BigInt& b, BigInt& g, BigInt& x, BigInt& y) {
    BigInt old_r = a;
    BigInt r = b;
    BigInt old_s(1);
    BigInt s(0);
    BigInt old_t(0);
    BigInt t(1);

    while (!r.is_zero()) {
        BigInt q = old_r.div(r);
        BigInt tmp = r;
        r = old_r.sub(q.mul(r));
        old_r = tmp;

        tmp = s;
        s = old_s.sub(q.mul(s));
        old_s = tmp;

        tmp = t;
        t = old_t.sub(q.mul(t));
        old_t = tmp;
    }
    g = old_r;
    x = old_s;
    y = old_t;
}

BigInt mod_inverse(const BigInt& a, const BigInt& m) {
    BigInt g, x, y;
    egcd(a, m, g, x, y);
    if (g.cmp(BigInt(1)) != 0) {
        throw BnError("modular inverse does not exist");
    }
    return x.mod(m);
}

BigInt lcm(const BigInt& a, const BigInt& b) {
    if (a.is_zero() || b.is_zero()) {
        return BigInt(0);
    }
    return a.div(gcd(a, b)).mul(b);
}

BigInt mod_exp_binary(const BigInt& base, const BigInt& exp, const BigInt& mod) {
    BigInt result(1);
    BigInt cur = base.mod(mod);
    const int bits = exp.bit_length();
    for (int i = 0; i < bits; ++i) {
        if (exp.bit_set(i)) {
            result = result.mod_mul(cur, mod);
        }
        cur = cur.mod_mul(cur, mod);
    }
    return result;
}

BigInt mod_exp(const BigInt& base, const BigInt& exp, const BigInt& mod) {
    thread_local BN_CTX* c = BN_CTX_new();
    if (!c) {
        throw BnError("BN_CTX_new failed");
    }
    BigInt r;
    if (BN_mod_exp(r.raw(), base.raw(), exp.raw(), mod.raw(), c) != 1) {
        throw BnError("BN_mod_exp failed");
    }
    return r;
}

bool miller_rabin(const BigInt& n, int rounds) {
    if (n.cmp(BigInt(2)) < 0) {
        return false;
    }
    if (n.cmp(BigInt(2)) == 0) {
        return true;
    }
    if (!n.is_odd()) {
        return false;
    }
    if (!trial_division(n)) {
        return false;
    }

    BigInt n_minus_1 = n.sub(BigInt(1));
    BigInt d = n_minus_1;
    int s = 0;
    while (!d.is_odd()) {
        d = d.div(BigInt(2));
        ++s;
    }

    BigInt two(2);
    for (int round = 0; round < rounds; ++round) {
        BigInt a = BigInt::random_bits(n.bit_length(), false);
        a = a.mod(n.sub(BigInt(3))).add(two);  // a ∈ [2, n-2]
        BigInt x = mod_exp(a, d, n);
        if (x.cmp(BigInt(1)) == 0 || x.cmp(n_minus_1) == 0) {
            continue;
        }
        bool witness = true;
        for (int j = 1; j < s; ++j) {
            x = x.mod_mul(x, n);
            if (x.cmp(n_minus_1) == 0) {
                witness = false;
                break;
            }
        }
        if (witness) {
            return false;
        }
    }
    return true;
}

BigInt generate_prime(int bits, ProgressFn progress) {
    int attempts = 0;
    for (;;) {
        BigInt cand = BigInt::random_bits(bits, true);
        ++attempts;
        if (progress && (attempts % 64 == 0)) {
            progress("поиск простого: испытание кандидата");
        }
        if (!trial_division(cand)) {
            continue;
        }
        if (miller_rabin(cand, kMillerRabinRounds)) {
            return cand;
        }
    }
}

KeyPair generate_keypair(int bits, ProgressFn progress) {
    if (bits < 16 || (bits % 2) != 0) {
        throw BnError("modulus bit length must be even and >= 16");
    }
    const int pbits = bits / 2;
    KeyPair kp;
    kp.e = BigInt(static_cast<unsigned long>(kPublicExponent));

    for (;;) {
        if (progress) {
            progress("генерация простого p");
        }
        kp.p = generate_prime(pbits, progress);
        if (progress) {
            progress("генерация простого q");
        }
        kp.q = generate_prime(pbits, progress);
        if (kp.p.cmp(kp.q) == 0) {
            continue;
        }
        if (kp.p.cmp(kp.q) < 0) {
            std::swap(kp.p, kp.q);
        }

        BigInt pm1 = kp.p.sub(BigInt(1));
        BigInt qm1 = kp.q.sub(BigInt(1));
        kp.lambda = lcm(pm1, qm1);
        if (gcd(kp.e, kp.lambda).cmp(BigInt(1)) != 0) {
            continue;
        }

        kp.n = kp.p.mul(kp.q);
        if (kp.n.bit_length() != bits) {
            continue;
        }
        kp.d = mod_inverse(kp.e, kp.lambda);
        kp.dp = kp.d.mod(pm1);
        kp.dq = kp.d.mod(qm1);
        kp.qinv = mod_inverse(kp.q, kp.p);
        return kp;
    }
}

}  