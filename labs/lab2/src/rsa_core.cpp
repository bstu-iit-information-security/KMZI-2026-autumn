#include "rsa_core.hpp"
#include "ct.hpp"
#include <cstdlib>
#include <cstring>

namespace rsa {

void to_limbs(const BigInt& x, uint64_t* out, size_t nlimbs) {
    if (mpz_size(x.get()) > nlimbs) std::abort();        // нарушение предусловия размера
    std::memset(out, 0, nlimbs * sizeof(uint64_t));
    size_t cnt = 0;
    mpz_export(out, &cnt, -1, sizeof(uint64_t), 0, 0, x.get());
}
void from_limbs(BigInt& x, const uint64_t* in, size_t nlimbs) {
    mpz_import(x.get(), nlimbs, -1, sizeof(uint64_t), 0, 0, in);
}

void int_to_bytes(const BigInt& x, uint8_t* out, size_t len) {
    uint64_t limbs[cfg::N_LIMBS];
    if (len > sizeof limbs) std::abort();
    to_limbs(x, limbs, len / 8);
    for (size_t i = 0; i < len; ++i)
        out[len - 1 - i] = static_cast<uint8_t>(limbs[i / 8] >> (8 * (i % 8)));
    ct::secure_zero(limbs, sizeof limbs);
}
void bytes_to_int(BigInt& x, const uint8_t* in, size_t len) {
    mpz_import(x.get(), len, 1, 1, 0, 0, in);
}

void encrypt_raw(BigInt& c, const BigInt& m, const PublicKey& pub) {
    nt::mod_pow(c, m, pub.e, pub.n, false);
}
void decrypt_plain(BigInt& m, const BigInt& c, const PrivateKey& prv) {
    nt::mod_pow(m, c, prv.d, prv.n, true);
}

// ---------------- constant-time (m1 - m2) mod p ----------------
void garner_diff_ct(BigInt& diff, const BigInt& m1, const BigInt& m2, const BigInt& p) {
    constexpr size_t L = cfg::P_LIMBS;
    uint64_t a[L], b[L], pl[L], t[L], pm[L];
    to_limbs(m1, a, L); to_limbs(m2, b, L); to_limbs(p, pl, L);

    // b := m2 mod p  (m2 < 2p -> достаточно одного условного вычитания; второе - запас прочности)
    for (int r = 0; r < 2; ++r) {
        uint64_t borrow = mpn_sub_n(t, b, pl, L);        // t = b - p, borrow = 1, если b < p
        uint64_t keep = 0 - borrow;                      // все единицы -> оставить b
        for (size_t i = 0; i < L; ++i) b[i] = ct::select64(keep, b[i], t[i]);
    }
    // t = m1 - b; если был заём, безусловно добавляем p & mask
    uint64_t borrow = mpn_sub_n(t, a, b, L);
    uint64_t mask = 0 - borrow;
    for (size_t i = 0; i < L; ++i) pm[i] = pl[i] & mask;
    mpn_add_n(t, t, pm, L);
    from_limbs(diff, t, L);

    ct::secure_zero(a, sizeof a); ct::secure_zero(b, sizeof b); ct::secure_zero(t, sizeof t);
    ct::secure_zero(pm, sizeof pm);
}

void garner_diff_naive(BigInt& diff, const BigInt& m1, const BigInt& m2, const BigInt& p) {
    mpz_sub(diff.get(), m1.get(), m2.get());
    if (mpz_cmp(m1.get(), m2.get()) < 0)                 // <-- ветвление по секретным данным
        mpz_add(diff.get(), diff.get(), p.get());
    mpz_mod(diff.get(), diff.get(), p.get());            // нормализация, если m2 > p
}

static void finish(BigInt& m, const BigInt& diff, const BigInt& m2, const BigInt& p,
                   const BigInt& q, const BigInt& qinv) {
    BigInt h;
    mpz_mul(h.get(), qinv.get(), diff.get());
    mpz_mod(h.get(), h.get(), p.get());                  // h = q_inv * (m1 - m2) mod p
    mpz_mul(h.get(), h.get(), q.get());
    mpz_add(m.get(), m2.get(), h.get());                 // m = m2 + h*q
}

void garner_combine_ct(BigInt& m, const BigInt& m1, const BigInt& m2,
                       const BigInt& p, const BigInt& q, const BigInt& qinv) {
    BigInt diff;
    garner_diff_ct(diff, m1, m2, p);
    finish(m, diff, m2, p, q, qinv);
}
void garner_combine_naive(BigInt& m, const BigInt& m1, const BigInt& m2,
                          const BigInt& p, const BigInt& q, const BigInt& qinv) {
    BigInt diff;
    garner_diff_naive(diff, m1, m2, p);
    finish(m, diff, m2, p, q, qinv);
}

void decrypt_crt(BigInt& m, const BigInt& c, const PrivateKey& prv) {
    BigInt cp, cq, m1, m2;
    mpz_mod(cp.get(), c.get(), prv.p.get());
    mpz_mod(cq.get(), c.get(), prv.q.get());
    nt::mod_pow(m1, cp, prv.dp, prv.p, true);            // m1 = c^dp mod p
    nt::mod_pow(m2, cq, prv.dq, prv.q, true);            // m2 = c^dq mod q
    garner_combine_ct(m, m1, m2, prv.p, prv.q, prv.qinv);
}

} // namespace rsa
