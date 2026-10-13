#ifndef ED_H
#define ED_H

#include <stdint.h>
#include "bn.h"

typedef struct {
    u256 X;
    u256 Y;
    u256 Z;
} ed_point;

typedef struct {
    u256 p;
    u256 a;
    u256 d;
    u256 q;
    u256 sqrt_m1;
    u256 e_sqrt;
    ed_point G;
} ed_params;

const ed_params *ed_curve(void);
void ed_identity(ed_point *r);
void ed_add(ed_point *r, const ed_point *P, const ed_point *Q);
void ed_double(ed_point *r, const ed_point *P);
void ed_multiply_vartime(ed_point *r, const u256 *k, const ed_point *P);
void ed_to_affine(u256 *x, u256 *y, const ed_point *P);
void ed_encode(uint8_t out[32], const ed_point *P);
int ed_decode(ed_point *P, const uint8_t in[32]);
uint64_t ed_equal(const ed_point *P, const ed_point *Q);

#endif
