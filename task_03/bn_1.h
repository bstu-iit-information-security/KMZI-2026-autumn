#ifndef BN_H
#define BN_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t w[4];
} u256;

void u256_zero(u256 *r);
void u256_from_u64(u256 *r, uint64_t v);
int u256_from_hex(u256 *r, const char *hex);
void u256_to_hex(const u256 *a, char *out);
void u256_from_le(u256 *r, const uint8_t b[32]);
void u256_to_le(const u256 *a, uint8_t b[32]);
void u256_shr(u256 *r, const u256 *a, unsigned n);
uint64_t u256_add(u256 *r, const u256 *a, const u256 *b);
uint64_t u256_sub(u256 *r, const u256 *a, const u256 *b);
uint64_t u256_lt(const u256 *a, const u256 *b);

void mod_add(u256 *r, const u256 *a, const u256 *b, const u256 *m);
void mod_sub(u256 *r, const u256 *a, const u256 *b, const u256 *m);
void mod_neg(u256 *r, const u256 *a, const u256 *m);
void mod_mul(u256 *r, const u256 *a, const u256 *b, const u256 *m);
void mod_sqr(u256 *r, const u256 *a, const u256 *m);
void mod_pow(u256 *r, const u256 *base, const u256 *e, const u256 *m);
void mod_inv(u256 *r, const u256 *a, const u256 *m);
void mod_reduce_bytes_le(u256 *r, const uint8_t *in, size_t len, const u256 *m);

#endif
