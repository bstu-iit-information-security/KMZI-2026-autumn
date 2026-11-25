#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include "bigint.hpp"

namespace rsa {

using bn::Big;
using bn::Mont;

inline void random_bytes(std::uint8_t* out, std::size_t n) {
    std::FILE* f = std::fopen("/dev/urandom", "rb");
    if (f == nullptr) std::abort();
    std::size_t got = std::fread(out, 1, n, f);
    std::fclose(f);
    if (got != n) std::abort();
}

inline Big gcd(Big a, Big b) {
    while (!bn::is_zero(b)) {
        Big q, r;
        bn::divmod(q, r, a, b);
        a = b;
        b = r;
    }
    return a;
}

inline bool mod_inverse(Big& out, const Big& a, const Big& m) {
    Big q, r0, r1, t0, t1;
    r0 = m;
    bn::divmod(q, r1, a, m);
    bn::set_zero(t0);
    bn::set_u64(t1, 1);
    while (!bn::is_zero(r1)) {
        Big qq, rr;
        bn::divmod(qq, rr, r0, r1);
        Big qt, qtm, junk, nt;
        bn::mul(qt, qq, t1);
        bn::divmod(junk, qtm, qt, m);
        if (bn::cmp(t0, qtm) >= 0) {
            bn::sub(nt, t0, qtm);
        } else {
            bn::add(nt, t0, m);
            bn::sub(nt, nt, qtm);
        }
        t0 = t1;
        t1 = nt;
        r0 = r1;
        r1 = rr;
    }
    if (!bn::eq_u64(r0, 1)) return false;
    out = t0;
    return true;
}

inline void mod_mul(Big& res, const Big& a, const Big& b, const Mont& m) {
    Big t;
    bn::mont_mul(t, a, b, m);
    bn::mont_mul(res, t, m.rr, m);
}

inline void mod_exp(Big& res, const Big& base, const Big& exp, const Mont& m) {
    Big b = base;
    if (bn::cmp(b, m.n) >= 0) {
        Big q;
        bn::divmod(q, b, base, m.n);
    }
    Big bm;
    bn::mont_mul(bm, b, m.rr, m);
    Big x = m.one;
    for (int i = bn::bitlen(exp) - 1; i >= 0; --i) {
        bn::mont_mul(x, x, x, m);
        if (bn::get_bit(exp, i)) bn::mont_mul(x, x, bm, m);
    }
    Big one = bn::from_u64(1);
    bn::mont_mul(res, x, one, m);
}

struct SmallPrimes {
    std::uint32_t p[400];
    int n;
    SmallPrimes() {
        n = 0;
        bool comp[2000];
        for (int i = 0; i < 2000; ++i) comp[i] = false;
        for (int i = 2; i < 2000; ++i) {
            if (comp[i]) continue;
            p[n++] = (std::uint32_t)i;
            for (int j = i * 2; j < 2000; j += i) comp[j] = true;
        }
    }
};

inline const SmallPrimes& small_primes() {
    static SmallPrimes sp;
    return sp;
}

inline bool miller_rabin(const Big& n, int rounds, const Mont& m) {
    Big one = bn::from_u64(1);
    Big two = bn::from_u64(2);
    Big three = bn::from_u64(3);
    Big nm1, nm3;
    bn::sub(nm1, n, one);
    bn::sub(nm3, n, three);
    Big d = nm1;
    int s = 0;
    while (!bn::get_bit(d, 0)) {
        bn::shr1(d);
        ++s;
    }
    std::uint8_t buf[512];
    std::size_t nbytes = (std::size_t)(bn::bitlen(n) + 7) / 8 + 8;
    for (int r = 0; r < rounds; ++r) {
        random_bytes(buf, nbytes);
        Big rnd, q, a;
        bn::from_bytes_be(rnd, buf, nbytes);
        bn::divmod(q, a, rnd, nm3);
        bn::add(a, a, two);
        Big x;
        mod_exp(x, a, d, m);
        if (bn::eq_u64(x, 1) || bn::cmp(x, nm1) == 0) continue;
        bool composite = true;
        for (int j = 1; j < s; ++j) {
            mod_mul(x, x, x, m);
            if (bn::cmp(x, nm1) == 0) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

inline void generate_prime(Big& p, int bits) {
    const SmallPrimes& sp = small_primes();
    std::uint8_t buf[512];
    std::size_t nbytes = (std::size_t)bits / 8;
    for (;;) {
        random_bytes(buf, nbytes);
        buf[0] |= 0xC0;
        buf[nbytes - 1] |= 1;
        bn::from_bytes_be(p, buf, nbytes);
        bool ok = true;
        for (int i = 0; i < sp.n; ++i) {
            if (bn::mod_small(p, sp.p[i]) == 0) {
                ok = false;
                break;
            }
        }
        if (!ok) continue;
        if (bn::mod_small(p, 65537) == 1) continue;
        Mont m;
        bn::mont_init(m, p);
        if (miller_rabin(p, 40, m)) return;
    }
}

struct PublicKey {
    Big n;
    Big e;
    Mont mn;
};

struct PrivateKey {
    Big n, e, d, p, q, dp, dq, qinv;
    Mont mn, mp, mq;
};

inline void generate_keypair(PublicKey& pub, PrivateKey& prv, int bits) {
    Big e = bn::from_u64(65537);
    Big one = bn::from_u64(1);
    for (;;) {
        Big p, q;
        generate_prime(p, bits / 2);
        generate_prime(q, bits / 2);
        int c = bn::cmp(p, q);
        if (c == 0) continue;
        Big diff;
        if (c > 0) bn::sub(diff, p, q);
        else bn::sub(diff, q, p);
        if (bn::bitlen(diff) < bits / 2 - 100) continue;
        Big p1, q1;
        bn::sub(p1, p, one);
        bn::sub(q1, q, one);
        Big g = gcd(p1, q1);
        Big t, r, lambda;
        bn::divmod(t, r, p1, g);
        bn::mul(lambda, t, q1);
        if (!bn::eq_u64(gcd(e, lambda), 1)) continue;
        Big d;
        if (!mod_inverse(d, e, lambda)) continue;
        Big n;
        bn::mul(n, p, q);
        Big dp, dq, qinv;
        bn::divmod(t, dp, d, p1);
        bn::divmod(t, dq, d, q1);
        if (!mod_inverse(qinv, q, p)) continue;
        prv.n = n;
        prv.e = e;
        prv.d = d;
        prv.p = p;
        prv.q = q;
        prv.dp = dp;
        prv.dq = dq;
        prv.qinv = qinv;
        bn::mont_init(prv.mn, n);
        bn::mont_init(prv.mp, p);
        bn::mont_init(prv.mq, q);
        pub.n = n;
        pub.e = e;
        pub.mn = prv.mn;
        return;
    }
}

}
