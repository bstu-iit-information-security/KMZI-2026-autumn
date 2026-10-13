#include "ed.h"
#include "ct.h"
#include <string.h>

static ed_params C;
static int ready = 0;

static void init(void)
{
    if (ready) {
        return;
    }
    u256 one, two, t;
    u256_from_u64(&one, 1);
    u256_from_u64(&two, 2);

    u256_from_hex(&C.p,
        "7fffffffffffffff" "ffffffffffffffff" "ffffffffffffffff" "ffffffffffffffed");
    u256_from_hex(&C.a,
        "7fffffffffffffff" "ffffffffffffffff" "ffffffffffffffff" "ffffffffffffffec");
    u256_from_hex(&C.d,
        "52036cee2b6ffe73" "8cc740797779e898" "00700a4d4141d8ab" "75eb4dca135978a3");
    u256_from_hex(&C.q,
        "1000000000000000" "0000000000000000" "14def9dea2f79cd6" "5812631a5cf5d3ed");
    u256_from_hex(&C.G.X,
        "216936d3cd6e53fe" "c0a4e231fdd6dc5c" "692cc7609525a7b2" "c9562d608f25d51a");
    u256_from_hex(&C.G.Y,
        "6666666666666666" "6666666666666666" "6666666666666666" "6666666666666658");
    u256_from_u64(&C.G.Z, 1);

    u256_sub(&t, &C.p, &one);
    u256_shr(&t, &t, 2);
    mod_pow(&C.sqrt_m1, &two, &t, &C.p);

    u256 five;
    u256_from_u64(&five, 5);
    u256_sub(&C.e_sqrt, &C.p, &five);
    u256_shr(&C.e_sqrt, &C.e_sqrt, 3);

    ready = 1;
}

const ed_params *ed_curve(void)
{
    init();
    return &C;
}

void ed_identity(ed_point *r)
{
    u256_zero(&r->X);
    u256_from_u64(&r->Y, 1);
    u256_from_u64(&r->Z, 1);
}

void ed_add(ed_point *r, const ed_point *P, const ed_point *Q)
{
    init();
    const u256 *p = &C.p;
    u256 A, B, Cc, D, E, F, G, t1, t2, t3, X3, Y3, Z3;

    mod_mul(&A, &P->Z, &Q->Z, p);
    mod_sqr(&B, &A, p);
    mod_mul(&Cc, &P->X, &Q->X, p);
    mod_mul(&D, &P->Y, &Q->Y, p);
    mod_mul(&t1, &Cc, &D, p);
    mod_mul(&E, &C.d, &t1, p);
    mod_sub(&F, &B, &E, p);
    mod_add(&G, &B, &E, p);

    mod_add(&t1, &P->X, &P->Y, p);
    mod_add(&t2, &Q->X, &Q->Y, p);
    mod_mul(&t3, &t1, &t2, p);
    mod_sub(&t3, &t3, &Cc, p);
    mod_sub(&t3, &t3, &D, p);

    mod_mul(&X3, &A, &F, p);
    mod_mul(&X3, &X3, &t3, p);

    mod_mul(&t1, &C.a, &Cc, p);
    mod_sub(&t1, &D, &t1, p);
    mod_mul(&Y3, &A, &G, p);
    mod_mul(&Y3, &Y3, &t1, p);

    mod_mul(&Z3, &F, &G, p);

    r->X = X3;
    r->Y = Y3;
    r->Z = Z3;
}

void ed_double(ed_point *r, const ed_point *P)
{
    ed_add(r, P, P);
}

void ed_multiply_vartime(ed_point *r, const u256 *k, const ed_point *P)
{
    ed_point R, B;
    ed_identity(&R);
    B = *P;
    for (int i = 255; i >= 0; i--) {
        ed_double(&R, &R);
        if ((k->w[i >> 6] >> (i & 63)) & 1) {
            ed_add(&R, &R, &B);
        }
    }
    *r = R;
}

void ed_to_affine(u256 *x, u256 *y, const ed_point *P)
{
    init();
    u256 zi;
    mod_inv(&zi, &P->Z, &C.p);
    mod_mul(x, &P->X, &zi, &C.p);
    mod_mul(y, &P->Y, &zi, &C.p);
}

void ed_encode(uint8_t out[32], const ed_point *P)
{
    u256 x, y;
    ed_to_affine(&x, &y, P);
    u256_to_le(&y, out);
    out[31] |= (uint8_t)((x.w[0] & 1) << 7);
}

int ed_decode(ed_point *P, const uint8_t in[32])
{
    init();
    const u256 *p = &C.p;
    uint8_t b[32];
    memcpy(b, in, 32);
    uint64_t sign = (uint64_t)(b[31] >> 7);
    b[31] &= 0x7f;

    u256 y;
    u256_from_le(&y, b);
    if (!u256_lt(&y, p)) {
        return -1;
    }

    u256 one, y2, u, v, v3, v7, t, x, vx2, nu;
    u256_from_u64(&one, 1);
    mod_sqr(&y2, &y, p);
    mod_sub(&u, &y2, &one, p);
    mod_mul(&t, &C.d, &y2, p);
    mod_add(&v, &t, &one, p);

    mod_sqr(&v3, &v, p);
    mod_mul(&v3, &v3, &v, p);
    mod_sqr(&v7, &v3, p);
    mod_mul(&v7, &v7, &v, p);

    mod_mul(&t, &u, &v7, p);
    mod_pow(&t, &t, &C.e_sqrt, p);
    mod_mul(&x, &u, &v3, p);
    mod_mul(&x, &x, &t, p);

    mod_sqr(&vx2, &x, p);
    mod_mul(&vx2, &vx2, &v, p);
    mod_neg(&nu, &u, p);

    uint64_t ok1 = ct_eq_u256(&vx2, &u);
    uint64_t ok2 = ct_eq_u256(&vx2, &nu);
    if (!ok1 && !ok2) {
        return -1;
    }
    if (!ok1) {
        mod_mul(&x, &x, &C.sqrt_m1, p);
    }

    u256 zero;
    u256_zero(&zero);
    if (ct_eq_u256(&x, &zero) && sign) {
        return -1;
    }
    if ((x.w[0] & 1) != sign) {
        mod_neg(&x, &x, p);
    }

    P->X = x;
    P->Y = y;
    u256_from_u64(&P->Z, 1);
    return 0;
}

uint64_t ed_equal(const ed_point *P, const ed_point *Q)
{
    init();
    u256 a, b, c, d;
    mod_mul(&a, &P->X, &Q->Z, &C.p);
    mod_mul(&b, &Q->X, &P->Z, &C.p);
    mod_mul(&c, &P->Y, &Q->Z, &C.p);
    mod_mul(&d, &Q->Y, &P->Z, &C.p);
    return ct_eq_u256(&a, &b) & ct_eq_u256(&c, &d);
}
