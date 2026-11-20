#include "eddsa.h"
#include "ct.h"
#include "sha512.h"
#include <string.h>

static void clamp(uint8_t h[32])
{
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
}

static void hash_scalar(u256 *out, const uint8_t *p1, size_t l1,
                        const uint8_t *p2, size_t l2,
                        const uint8_t *p3, size_t l3,
                        const u256 *q)
{
    sha512_ctx c;
    uint8_t d[64];
    sha512_init(&c);
    sha512_update(&c, p1, l1);
    sha512_update(&c, p2, l2);
    sha512_update(&c, p3, l3);
    sha512_final(&c, d);
    mod_reduce_bytes_le(out, d, 64, q);
    ct_wipe(d, sizeof d);
}

void eddsa_keygen(eddsa_key *k, const uint8_t seed[32])
{
    const ed_params *c = ed_curve();
    uint8_t h[64];
    ed_point A;

    sha512(seed, 32, h);
    memcpy(k->seed, seed, 32);
    memcpy(k->prefix, h + 32, 32);
    clamp(h);
    u256_from_le(&k->a, h);

    ct_scalar_mul(&A, &k->a, &c->G);
    ed_encode(k->pub, &A);

    ct_wipe(h, sizeof h);
    ct_wipe(&A, sizeof A);
}

void eddsa_sign(uint8_t sig[64], const eddsa_key *k, const uint8_t *msg, size_t len)
{
    const ed_params *c = ed_curve();
    u256 r, h, aq, t, S;
    ed_point R;
    uint8_t ab[32];

    hash_scalar(&r, k->prefix, 32, msg, len, NULL, 0, &c->q);

    ct_scalar_mul(&R, &r, &c->G);
    ed_encode(sig, &R);

    hash_scalar(&h, sig, 32, k->pub, 32, msg, len, &c->q);

    u256_to_le(&k->a, ab);
    mod_reduce_bytes_le(&aq, ab, 32, &c->q);

    mod_mul(&t, &h, &aq, &c->q);
    mod_add(&S, &r, &t, &c->q);
    u256_to_le(&S, sig + 32);

    ct_wipe(&r, sizeof r);
    ct_wipe(&aq, sizeof aq);
    ct_wipe(&t, sizeof t);
    ct_wipe(ab, sizeof ab);
    ct_wipe(&R, sizeof R);
}

int eddsa_verify(const uint8_t sig[64], const uint8_t pub[32], const uint8_t *msg, size_t len)
{
    const ed_params *c = ed_curve();
    ed_point R, A, L, hA, Rr;
    u256 S, h;

    if (ed_decode(&R, sig) != 0) {
        return 0;
    }
    if (ed_decode(&A, pub) != 0) {
        return 0;
    }
    u256_from_le(&S, sig + 32);
    if (!u256_lt(&S, &c->q)) {
        return 0;
    }

    hash_scalar(&h, sig, 32, pub, 32, msg, len, &c->q);

    ed_multiply_vartime(&L, &S, &c->G);
    ed_multiply_vartime(&hA, &h, &A);
    ed_add(&Rr, &R, &hA);

    return (int)ed_equal(&L, &Rr);
}

int eddsa_ecdh(u256 *shared_x, const eddsa_key *self, const uint8_t peer_pub[32])
{
    ed_point Q, K;
    u256 y;

    if (ed_decode(&Q, peer_pub) != 0) {
        return -1;
    }
    ct_scalar_mul(&K, &self->a, &Q);
    ed_to_affine(shared_x, &y, &K);
    ct_wipe(&K, sizeof K);
    return 0;
}
