#include "numtheory.hpp"
#include "random.hpp"
#include "ct.hpp"
#include "config.hpp"
#include <cstdlib>

BigInt::~BigInt() {
    size_t n = mpz_size(v_);
    if (n) ct::secure_zero(mpz_limbs_modify(v_, static_cast<mp_size_t>(n)), n * sizeof(mp_limb_t));
    mpz_clear(v_);
}

namespace nt {

void ext_gcd(BigInt& g, BigInt& x, BigInt& y, const BigInt& a, const BigInt& b) {
    BigInt old_r(0), r(0), old_s(1), s(0), old_t(0), t(1), q, rem, tmp, nxt;
    mpz_set(old_r.get(), a.get());
    mpz_set(r.get(), b.get());
    while (mpz_cmp_ui(r.get(), 0) != 0) {
        mpz_tdiv_qr(q.get(), rem.get(), old_r.get(), r.get());
        mpz_set(old_r.get(), r.get());  mpz_set(r.get(), rem.get());

        mpz_mul(tmp.get(), q.get(), s.get());
        mpz_sub(nxt.get(), old_s.get(), tmp.get());
        mpz_set(old_s.get(), s.get());  mpz_set(s.get(), nxt.get());

        mpz_mul(tmp.get(), q.get(), t.get());
        mpz_sub(nxt.get(), old_t.get(), tmp.get());
        mpz_set(old_t.get(), t.get());  mpz_set(t.get(), nxt.get());
    }
    mpz_set(g.get(), old_r.get());
    mpz_set(x.get(), old_s.get());
    mpz_set(y.get(), old_t.get());
}

bool mod_inverse(BigInt& r, const BigInt& a, const BigInt& m) {
    BigInt am, g, x, y;
    mpz_mod(am.get(), a.get(), m.get());
    ext_gcd(g, x, y, am, m);
    if (mpz_cmp_ui(g.get(), 1) != 0) return false;
    mpz_mod(r.get(), x.get(), m.get());   // mpz_mod всегда возвращает неотрицательный остаток
    return true;
}

void mod_pow(BigInt& r, const BigInt& base, const BigInt& exp, const BigInt& m, bool secret) {
    if (secret) mpz_powm_sec(r.get(), base.get(), exp.get(), m.get());
    else        mpz_powm(r.get(), base.get(), exp.get(), m.get());
}

void random_bits(BigInt& r, size_t bits, bool top2) {
    uint8_t buf[512];                                   // фиксированный буфер, до 4096 бит
    if (bits == 0 || bits > 4096) std::abort();
    size_t nbytes = (bits + 7) / 8;
    random_bytes(buf, nbytes);
    if (bits % 8) buf[0] &= static_cast<uint8_t>(0xFFu >> (8 - bits % 8));
    mpz_import(r.get(), nbytes, 1, 1, 0, 0, buf);
    ct::secure_zero(buf, sizeof buf);
    mpz_setbit(r.get(), bits - 1);
    if (top2) mpz_setbit(r.get(), bits - 2);
}

bool miller_rabin(const BigInt& n, int rounds) {
    if (mpz_cmp_ui(n.get(), 4) < 0) return mpz_cmp_ui(n.get(), 2) >= 0;
    if (!mpz_tstbit(n.get(), 0)) return false;
    BigInt nm1, d, a, x, range;
    mpz_sub_ui(nm1.get(), n.get(), 1);
    mpz_set(d.get(), nm1.get());
    unsigned long s = 0;
    while (!mpz_tstbit(d.get(), 0)) { mpz_tdiv_q_2exp(d.get(), d.get(), 1); ++s; }
    mpz_sub_ui(range.get(), n.get(), 3);                // a in [2, n-2]
    for (int i = 0; i < rounds; ++i) {
        random_bits(a, n.bits(), false);
        mpz_mod(a.get(), a.get(), range.get());
        mpz_add_ui(a.get(), a.get(), 2);
        mpz_powm(x.get(), a.get(), d.get(), n.get());
        if (mpz_cmp_ui(x.get(), 1) == 0 || mpz_cmp(x.get(), nm1.get()) == 0) continue;
        bool composite = true;
        for (unsigned long j = 1; j < s; ++j) {
            mpz_mul(x.get(), x.get(), x.get());
            mpz_mod(x.get(), x.get(), n.get());
            if (mpz_cmp(x.get(), nm1.get()) == 0) { composite = false; break; }
        }
        if (composite) return false;
    }
    return true;
}

void gen_prime(BigInt& p, size_t bits, uint32_t e) {
    for (;;) {
        random_bits(p, bits, true);
        mpz_setbit(p.get(), 0);                          // нечетное
        bool ok = true;
        for (unsigned long dv = 3; dv < 2000 && ok; dv += 2)   // пробное деление
            if (mpz_fdiv_ui(p.get(), dv) == 0) ok = false;
        if (!ok) continue;
        if (mpz_fdiv_ui(p.get(), e) == 1) continue;      // gcd(e, p-1) = 1 (e простое)
        if (miller_rabin(p, cfg::MR_ROUNDS)) return;
    }
}

} // namespace nt

namespace nt {
void generate_keypair(PublicKey& pub, PrivateKey& prv, size_t bits, uint32_t e) {
    const size_t half = bits / 2;
    BigInt p, q, pm1, qm1, g, x, y, lam, diff, prod;
    BigInt ebig(e);
    for (;;) {
        gen_prime(p, half, e);
        gen_prime(q, half, e);
        mpz_sub(diff.get(), p.get(), q.get());
        mpz_abs(diff.get(), diff.get());
        if (diff.bits() < half - 100) continue;          // p и q не должны быть близки (метод Ферма)
        mpz_sub_ui(pm1.get(), p.get(), 1);
        mpz_sub_ui(qm1.get(), q.get(), 1);
        // lambda = lcm(p-1, q-1) = (p-1)(q-1)/gcd
        ext_gcd(g, x, y, pm1, qm1);
        mpz_mul(prod.get(), pm1.get(), qm1.get());
        mpz_tdiv_qr(lam.get(), x.get(), prod.get(), g.get());
        if (!mod_inverse(prv.d, ebig, lam)) continue;
        break;
    }
    mpz_mul(prv.n.get(), p.get(), q.get());
    mpz_set(prv.p.get(), p.get());  mpz_set(prv.q.get(), q.get());
    mpz_set(prv.e.get(), ebig.get());
    mpz_mod(prv.dp.get(), prv.d.get(), pm1.get());       // d_p = d mod (p-1)
    mpz_mod(prv.dq.get(), prv.d.get(), qm1.get());       // d_q = d mod (q-1)
    if (!mod_inverse(prv.qinv, q, p)) std::abort();      // q_inv = q^{-1} mod p
    mpz_set(pub.n.get(), prv.n.get());
    mpz_set(pub.e.get(), ebig.get());
}
} // namespace nt
