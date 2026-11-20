#include "bn.h"
#include "ct.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

void u256_zero(u256 *r)
{
    for (int i = 0; i < 4; i++) {
        r->w[i] = 0;
    }
}

void u256_from_u64(u256 *r, uint64_t v)
{
    u256_zero(r);
    r->w[0] = v;
}

int u256_from_hex(u256 *r, const char *hex)
{
    size_t n = strlen(hex);
    if (n == 0 || n > 64) {
        return -1;
    }
    u256_zero(r);
    for (size_t i = 0; i < n; i++) {
        char c = hex[i];
        uint64_t v;
        if (c >= '0' && c <= '9') {
            v = (uint64_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v = (uint64_t)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            v = (uint64_t)(c - 'A' + 10);
        } else {
            return -1;
        }
        for (int j = 3; j > 0; j--) {
            r->w[j] = (r->w[j] << 4) | (r->w[j - 1] >> 60);
        }
        r->w[0] = (r->w[0] << 4) | v;
    }
    return 0;
}

void u256_to_hex(const u256 *a, char *out)
{
    for (int i = 3; i >= 0; i--) {
        sprintf(out + 16 * (3 - i), "%016" PRIx64, a->w[i]);
    }
}

void u256_from_le(u256 *r, const uint8_t b[32])
{
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--) {
            v = (v << 8) | b[8 * i + j];
        }
        r->w[i] = v;
    }
}

void u256_to_le(const u256 *a, uint8_t b[32])
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            b[8 * i + j] = (uint8_t)(a->w[i] >> (8 * j));
        }
    }
}

void u256_shr(u256 *r, const u256 *a, unsigned n)
{
    u256 t;
    for (int i = 0; i < 4; i++) {
        uint64_t hi = (i < 3) ? (a->w[i + 1] << (64 - n)) : 0;
        t.w[i] = (a->w[i] >> n) | hi;
    }
    *r = t;
}

uint64_t u256_add(u256 *r, const u256 *a, const u256 *b)
{
    unsigned __int128 c = 0;
    for (int i = 0; i < 4; i++) {
        c += (unsigned __int128)a->w[i] + b->w[i];
        r->w[i] = (uint64_t)c;
        c >>= 64;
    }
    return (uint64_t)c;
}

uint64_t u256_sub(u256 *r, const u256 *a, const u256 *b)
{
    uint64_t br = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t ai = a->w[i];
        uint64_t bi = b->w[i];
        uint64_t d = ai - bi;
        uint64_t b1 = (uint64_t)(ai < bi);
        uint64_t d2 = d - br;
        uint64_t b2 = (uint64_t)(d < br);
        r->w[i] = d2;
        br = b1 | b2;
    }
    return br;
}

uint64_t u256_lt(const u256 *a, const u256 *b)
{
    u256 t;
    return u256_sub(&t, a, b);
}

void mod_add(u256 *r, const u256 *a, const u256 *b, const u256 *m)
{
    u256 t, s;
    uint64_t c = u256_add(&t, a, b);
    uint64_t bw = u256_sub(&s, &t, m);
    uint64_t use = (c | (bw ^ 1)) & 1;
    ct_select_u256(r, &s, &t, use);
}

void mod_sub(u256 *r, const u256 *a, const u256 *b, const u256 *m)
{
    u256 t, u;
    uint64_t bw = u256_sub(&t, a, b);
    u256_add(&u, &t, m);
    ct_select_u256(r, &u, &t, bw);
}

void mod_neg(u256 *r, const u256 *a, const u256 *m)
{
    u256 z;
    u256_zero(&z);
    mod_sub(r, &z, a, m);
}

void mod_mul(u256 *r, const u256 *a, const u256 *b, const u256 *m)
{
    u256 acc, t;
    u256_zero(&acc);
    for (int i = 255; i >= 0; i--) {
        uint64_t bit = (b->w[i >> 6] >> (i & 63)) & 1;
        mod_add(&acc, &acc, &acc, m);
        mod_add(&t, &acc, a, m);
        ct_select_u256(&acc, &t, &acc, bit);
    }
    *r = acc;
}

void mod_sqr(u256 *r, const u256 *a, const u256 *m)
{
    mod_mul(r, a, a, m);
}

void mod_pow(u256 *r, const u256 *base, const u256 *e, const u256 *m)
{
    u256 bs = *base;
    u256 res, t;
    u256_from_u64(&res, 1);
    for (int i = 255; i >= 0; i--) {
        uint64_t bit = (e->w[i >> 6] >> (i & 63)) & 1;
        mod_mul(&res, &res, &res, m);
        mod_mul(&t, &res, &bs, m);
        ct_select_u256(&res, &t, &res, bit);
    }
    *r = res;
}

void mod_inv(u256 *r, const u256 *a, const u256 *m)
{
    u256 two, e;
    u256_from_u64(&two, 2);
    u256_sub(&e, m, &two);
    mod_pow(r, a, &e, m);
}

void mod_reduce_bytes_le(u256 *r, const uint8_t *in, size_t len, const u256 *m)
{
    u256 acc, one, t;
    u256_zero(&acc);
    u256_from_u64(&one, 1);
    for (size_t i = len; i > 0; i--) {
        for (int j = 7; j >= 0; j--) {
            uint64_t bit = (in[i - 1] >> j) & 1;
            mod_add(&acc, &acc, &acc, m);
            mod_add(&t, &acc, &one, m);
            ct_select_u256(&acc, &t, &acc, bit);
        }
    }
    *r = acc;
}
