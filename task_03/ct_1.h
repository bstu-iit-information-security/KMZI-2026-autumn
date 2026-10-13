#ifndef CT_H
#define CT_H

#include <stdint.h>
#include <stddef.h>
#include "bn.h"
#include "ed.h"

static inline uint64_t ct_mask(uint64_t bit)
{
    return (uint64_t)0 - (bit & 1);
}

static inline uint64_t ct_is_zero_u64(uint64_t x)
{
    return ((x | ((uint64_t)0 - x)) >> 63) ^ 1;
}

static inline void ct_select_u256(u256 *r, const u256 *a, const u256 *b, uint64_t bit)
{
    uint64_t mask = ct_mask(bit);
    for (int i = 0; i < 4; i++) {
        r->w[i] = b->w[i] ^ (mask & (a->w[i] ^ b->w[i]));
    }
}

static inline void ct_cswap_u256(u256 *x, u256 *y, uint64_t bit)
{
    uint64_t mask = ct_mask(bit);
    for (int i = 0; i < 4; i++) {
        uint64_t dummy = mask & (x->w[i] ^ y->w[i]);
        x->w[i] ^= dummy;
        y->w[i] ^= dummy;
    }
}

static inline uint64_t ct_eq_u256(const u256 *a, const u256 *b)
{
    uint64_t acc = 0;
    for (int i = 0; i < 4; i++) {
        acc |= a->w[i] ^ b->w[i];
    }
    return ct_is_zero_u64(acc);
}

static inline void ct_cswap_point(ed_point *P, ed_point *Q, uint64_t bit)
{
    ct_cswap_u256(&P->X, &Q->X, bit);
    ct_cswap_u256(&P->Y, &Q->Y, bit);
    ct_cswap_u256(&P->Z, &Q->Z, bit);
}

static inline void ct_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) {
        *v++ = 0;
    }
}

void ct_scalar_mul(ed_point *r, const u256 *k, const ed_point *P);
uint64_t ct_compare_bytes(const uint8_t *a, const uint8_t *b, size_t n);

#endif
