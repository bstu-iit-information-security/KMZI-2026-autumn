#include "ct.h"
#include <fstream>

void random_bytes(uint8_t* out, size_t n) {
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom) throw std::runtime_error("CSPRNG недоступен");
    urandom.read(reinterpret_cast<char*>(out), n);
    if (!urandom) throw std::runtime_error("CSPRNG: чтение не удалось");
}

void secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;
}

void secure_clear_mpz(mpz_class& z) {
    mpz_ptr zp = z.get_mpz_t();
    size_t n = mpz_size(zp);
    if (n > 0) {
        mp_limb_t* limbs = mpz_limbs_write(zp, n);
        secure_zero(limbs, n * sizeof(mp_limb_t));
        mpz_limbs_finish(zp, 0);
    } else {
        mpz_set_ui(zp, 0);
    }
}

int secure_compare(const mpz_class& a, const mpz_class& b) {
    mpz_class d = a - b;
    int s = mpz_sgn(d.get_mpz_t());
    secure_clear_mpz(d);
    return s;
}

mpz_class generate_scalar_ct(const mpz_class& q, size_t iters) {
    if (iters == 0)              throw std::invalid_argument("iters must be > 0");
    if (mpz_sgn(q.get_mpz_t()) <= 0)
                                 throw std::invalid_argument("q must be > 0");

    const size_t nbits  = mpz_sizeinbase(q.get_mpz_t(), 2);
    const size_t nbytes = (nbits + 7) / 8;
    if (nbytes > 64)
        throw std::runtime_error("scalar too large for static buffer");
    uint8_t buf[64];

    mpz_class k = 0;
    mpz_class found_mask = 0;

    for (size_t i = 0; i < iters; ++i) {
        random_bytes(buf, nbytes);
        mpz_class cand;
        mpz_import(cand.get_mpz_t(), nbytes, 1, 1, 1, 0, buf);

        if (nbits < nbytes * 8) {
            mpz_class bitmask = (mpz_class(1) << nbits) - 1;
            cand &= bitmask;
            secure_clear_mpz(bitmask);
        }

        int s1 = secure_compare(cand, mpz_class(0));
        int s2 = secure_compare(q,    cand);
        int valid = (s1 > 0) & (s2 > 0);

        mpz_class valid_mask = mpz_class(0) - mpz_class(valid);
        mpz_class take_mask  = valid_mask & ~found_mask;

        k = (cand & take_mask) | (k & ~take_mask);

        found_mask |= valid_mask;

        secure_clear_mpz(cand);
        secure_clear_mpz(valid_mask);
        secure_clear_mpz(take_mask);
    }

    secure_zero(buf, sizeof(buf));
    secure_clear_mpz(found_mask);

    if (mpz_sgn(k.get_mpz_t()) <= 0)
        throw std::runtime_error(
            "generate_scalar_ct: 100 итераций без валидного k");

    return k;
}

Point secure_multiply(const mpz_class& k, const Point& P, const CurveParams& C) {
    if (P.is_infinity)
        throw std::invalid_argument("secure_multiply: P = O");
    if (mpz_sgn(k.get_mpz_t()) <= 0)
        throw std::invalid_argument("secure_multiply: k must be > 0");
    if (!is_on_curve(P, C))
        throw std::invalid_argument("secure_multiply: P не на кривой");

    Point R = scalar_multiply(k, P, C);
    return R;
}