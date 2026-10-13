#include "ct.h"

void ct_scalar_mul(ed_point *r, const u256 *k, const ed_point *P)
{
    ed_point R0, R1;
    ed_identity(&R0);
    R1 = *P;

    for (int i = 254; i >= 0; i--) {
        uint64_t bit = (k->w[i >> 6] >> (i & 63)) & 1;
        ct_cswap_point(&R0, &R1, bit);
        ed_add(&R1, &R0, &R1);
        ed_double(&R0, &R0);
        ct_cswap_point(&R0, &R1, bit);
    }

    *r = R0;
    ct_wipe(&R0, sizeof R0);
    ct_wipe(&R1, sizeof R1);
}

uint64_t ct_compare_bytes(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint64_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc |= (uint64_t)(a[i] ^ b[i]);
    }
    return ct_is_zero_u64(acc);
}
