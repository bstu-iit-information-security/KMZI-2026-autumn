#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <chrono>

using namespace std;

#define N_LIMBS  128
#define N_BYTES  512
#define HASH_LEN 32
#define K_LEN    128
#define PRIME_BITS 512

typedef uint32_t u32;
typedef uint64_t u64;

struct BigInt { u32 v[N_LIMBS]; };

static u32 g_mp = 0;
static u64 g_rng = 0x123456789ABCDEF0ULL;

static u32 rng32() {
    g_rng = g_rng * 6364136223846793005ULL + 1442695040888963407ULL;
    return (u32)(g_rng >> 32);
}

static void bi_zero(BigInt* x) { memset(x->v, 0, sizeof(x->v)); }
static void bi_set_u32(BigInt* x, u32 val) { bi_zero(x); x->v[0] = val; }
static void bi_copy(BigInt* d, const BigInt* s) { memcpy(d->v, s->v, sizeof(s->v)); }

static int bi_is_zero(const BigInt* x) {
    u32 acc = 0;
    for (int i = 0; i < N_LIMBS; i++) acc |= x->v[i];
    return acc == 0;
}

static int bi_is_one(const BigInt* x) {
    if (x->v[0] != 1) return 0;
    for (int i = 1; i < N_LIMBS; i++) if (x->v[i]) return 0;
    return 1;
}

static int bi_cmp(const BigInt* a, const BigInt* b) {
    for (int i = N_LIMBS - 1; i >= 0; i--) {
        if (a->v[i] > b->v[i]) return 1;
        if (a->v[i] < b->v[i]) return -1;
    }
    return 0;
}

static int bi_ge_ct(const BigInt* a, const BigInt* b) {
    u64 borrow = 0;
    for (int i = 0; i < N_LIMBS; i++) {
        u64 t = (u64)a->v[i] - (u64)b->v[i] - borrow;
        borrow = (t >> 32) & 1;
    }
    return (int)(borrow ^ 1);
}

static void bi_add(BigInt* r, const BigInt* a, const BigInt* b) {
    u64 carry = 0;
    for (int i = 0; i < N_LIMBS; i++) {
        u64 t = (u64)a->v[i] + (u64)b->v[i] + carry;
        r->v[i] = (u32)t;
        carry = t >> 32;
    }
}

static void bi_sub(BigInt* r, const BigInt* a, const BigInt* b) {
    u64 borrow = 0;
    for (int i = 0; i < N_LIMBS; i++) {
        u64 t = (u64)a->v[i] - (u64)b->v[i] - borrow;
        r->v[i] = (u32)t;
        borrow = (t >> 32) & 1;
    }
}

static u32 bi_sub_b(BigInt* r, const BigInt* a, const BigInt* b) {
    u64 borrow = 0;
    for (int i = 0; i < N_LIMBS; i++) {
        u64 t = (u64)a->v[i] - (u64)b->v[i] - borrow;
        r->v[i] = (u32)t;
        borrow = (t >> 32) & 1;
    }
    return (u32)borrow;
}

static void bi_shl1(BigInt* r, const BigInt* a) {
    u32 carry = 0;
    for (int i = 0; i < N_LIMBS; i++) {
        u32 nc = a->v[i] >> 31;
        r->v[i] = (a->v[i] << 1) | carry;
        carry = nc;
    }
}

static void bi_shr1(BigInt* r, const BigInt* a) {
    u32 carry = 0;
    for (int i = N_LIMBS - 1; i >= 0; i--) {
        u32 nc = a->v[i] & 1;
        r->v[i] = (a->v[i] >> 1) | (carry << 31);
        carry = nc;
    }
}

static int bi_bit(const BigInt* a, int i) {
    return (a->v[i >> 5] >> (i & 31)) & 1;
}

static int bi_bitlen(const BigInt* a) {
    for (int i = N_LIMBS - 1; i >= 0; i--) {
        if (a->v[i]) {
            int b = 0;
            u32 x = a->v[i];
            while (x) { b++; x >>= 1; }
            return i * 32 + b;
        }
    }
    return 0;
}

static void bi_from_bytes(BigInt* r, const uint8_t* b, size_t len) {
    bi_zero(r);
    for (size_t i = 0; i < len; i++) {
        u32 byte = b[len - 1 - i];
        int limb = i / 4;
        int shift = (i % 4) * 8;
        if (limb < N_LIMBS) r->v[limb] |= byte << shift;
    }
}

static void bi_to_bytes(const BigInt* a, uint8_t* b, size_t len) {
    memset(b, 0, len);
    for (size_t i = 0; i < len; i++) {
        u32 limb = a->v[i / 4];
        u32 byte = (limb >> ((i % 4) * 8)) & 0xFF;
        b[len - 1 - i] = (uint8_t)byte;
    }
}

static void mont_setup(u32 m0) {
    u32 inv = 1;
    for (int i = 0; i < 5; i++) inv *= 2 - m0 * inv;
    g_mp = (u32)0 - inv;
}

static void mont_mul(BigInt* r, const BigInt* a, const BigInt* b, const BigInt* m) {
    u32 t[N_LIMBS + 2];
    memset(t, 0, sizeof(t));
    for (int i = 0; i < N_LIMBS; i++) {
        u64 C = 0;
        for (int j = 0; j < N_LIMBS; j++) {
            u64 s = (u64)t[j] + (u64)a->v[j] * b->v[i] + C;
            t[j] = (u32)s;
            C = s >> 32;
        }
        u64 s = (u64)t[N_LIMBS] + C;
        t[N_LIMBS] = (u32)s;
        t[N_LIMBS + 1] = (u32)(s >> 32);

        u32 mi = t[0] * g_mp;
        C = 0;
        for (int j = 0; j < N_LIMBS; j++) {
            u64 s2 = (u64)t[j] + (u64)mi * m->v[j] + C;
            if (j > 0) t[j - 1] = (u32)s2;
            C = s2 >> 32;
        }
        s = (u64)t[N_LIMBS] + C;
        t[N_LIMBS - 1] = (u32)s;
        t[N_LIMBS] = t[N_LIMBS + 1] + (u32)(s >> 32);
    }
    for (int i = 0; i < N_LIMBS; i++) r->v[i] = t[i];
    if (bi_ge_ct(r, m)) bi_sub(r, r, m);
}

static void mont_from(BigInt* r, const BigInt* a, const BigInt* m) {
    BigInt t;
    bi_copy(&t, a);
    for (int i = 0; i < 32 * N_LIMBS; i++) {
        bi_shl1(&t, &t);
        if (bi_ge_ct(&t, m)) bi_sub(&t, &t, m);
    }
    bi_copy(r, &t);
}

static void mont_modexp(BigInt* r, const BigInt* base, const BigInt* exp, const BigInt* m) {
    mont_setup(m->v[0]);
    BigInt R0, R1, t, one;
    bi_set_u32(&one, 1);
    mont_from(&R0, &one, m);
    mont_from(&R1, base, m);
    int bits = bi_bitlen(exp);
    for (int i = bits - 1; i >= 0; i--) {
        int bit = bi_bit(exp, i);
        u32 mask = (u32)0 - (u32)bit;
        for (int j = 0; j < N_LIMBS; j++) {
            u32 d = (R0.v[j] ^ R1.v[j]) & mask;
            R0.v[j] ^= d;
            R1.v[j] ^= d;
        }
        mont_mul(&t, &R0, &R1, m);
        bi_copy(&R1, &t);
        mont_mul(&t, &R0, &R0, m);
        bi_copy(&R0, &t);
        for (int j = 0; j < N_LIMBS; j++) {
            u32 d = (R0.v[j] ^ R1.v[j]) & mask;
            R0.v[j] ^= d;
            R1.v[j] ^= d;
        }
    }
    mont_mul(r, &R0, &one, m);
}

static void sha256_transform(u32 st[8], const uint8_t blk[64]) {
    static const u32 K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    u32 w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((u32)blk[4 * i] << 24) | ((u32)blk[4 * i + 1] << 16)
            | ((u32)blk[4 * i + 2] << 8) | (u32)blk[4 * i + 3];
    }
    for (int i = 16; i < 64; i++) {
        u32 s0 = (w[i - 15] >> 7 | w[i - 15] << 25) ^ (w[i - 15] >> 18 | w[i - 15] << 14) ^ (w[i - 15] >> 3);
        u32 s1 = (w[i - 2] >> 17 | w[i - 2] << 15) ^ (w[i - 2] >> 19 | w[i - 2] << 13) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; i++) {
        u32 S1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7);
        u32 ch = (e & f) ^ (~e & g);
        u32 t1 = h + S1 + ch + K[i] + w[i];
        u32 S0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10);
        u32 mj = (a & b) ^ (a & c) ^ (b & c);
        u32 t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

static void sha256(const uint8_t* msg, size_t len, uint8_t out[32]) {
    u32 st[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    size_t i;
    uint8_t blk[64];
    for (i = 0; i + 64 <= len; i += 64) sha256_transform(st, msg + i);
    size_t rem = len - i;
    memset(blk, 0, 64);
    memcpy(blk, msg + i, rem);
    blk[rem] = 0x80;
    if (rem >= 56) {
        sha256_transform(st, blk);
        memset(blk, 0, 64);
    }
    u64 bits = (u64)len * 8;
    for (int j = 0; j < 8; j++) blk[63 - j] = (uint8_t)(bits >> (8 * j));
    sha256_transform(st, blk);
    for (int j = 0; j < 8; j++) {
        out[4 * j + 0] = (uint8_t)(st[j] >> 24);
        out[4 * j + 1] = (uint8_t)(st[j] >> 16);
        out[4 * j + 2] = (uint8_t)(st[j] >> 8);
        out[4 * j + 3] = (uint8_t)(st[j]);
    }
}

static void mgf1(const uint8_t* seed, size_t seed_len, uint8_t* mask, size_t mask_len) {
    uint8_t buf[128 + 4];
    size_t off = 0;
    u32 counter = 0;
    while (off < mask_len) {
        memcpy(buf, seed, seed_len);
        buf[seed_len + 0] = (uint8_t)(counter >> 24);
        buf[seed_len + 1] = (uint8_t)(counter >> 16);
        buf[seed_len + 2] = (uint8_t)(counter >> 8);
        buf[seed_len + 3] = (uint8_t)(counter);
        uint8_t h[32];
        sha256(buf, seed_len + 4, h);
        size_t n = mask_len - off;
        if (n > 32) n = 32;
        memcpy(mask + off, h, n);
        off += n;
        counter++;
    }
}

static int oaep_encode(const uint8_t* msg, size_t msg_len,
    const uint8_t* label, size_t label_len,
    const uint8_t* seed,
    uint8_t* em) {
    const size_t hLen = HASH_LEN;
    const size_t k = K_LEN;
    const size_t db_len = k - hLen - 1;
    if (msg_len > db_len - hLen - 1) return -1;

    uint8_t lHash[32];
    sha256(label, label_len, lHash);

    uint8_t DB[K_LEN];
    size_t ps_len = db_len - hLen - 1 - msg_len;
    memcpy(DB, lHash, hLen);
    memset(DB + hLen, 0x00, ps_len);
    DB[hLen + ps_len] = 0x01;
    memcpy(DB + hLen + ps_len + 1, msg, msg_len);

    uint8_t dbMask[K_LEN];
    mgf1(seed, hLen, dbMask, db_len);
    uint8_t maskedDB[K_LEN];
    for (size_t i = 0; i < db_len; i++) maskedDB[i] = DB[i] ^ dbMask[i];

    uint8_t seedMask[32];
    mgf1(maskedDB, db_len, seedMask, hLen);
    uint8_t maskedSeed[32];
    for (size_t i = 0; i < hLen; i++) maskedSeed[i] = seed[i] ^ seedMask[i];

    em[0] = 0x00;
    memcpy(em + 1, maskedSeed, hLen);
    memcpy(em + 1 + hLen, maskedDB, db_len);
    return 0;
}

static int oaep_decode_ct(const uint8_t* em,
    const uint8_t* label, size_t label_len,
    uint8_t* msg, size_t* msg_len) {
    const size_t hLen = HASH_LEN;
    const size_t k = K_LEN;
    const size_t db_len = k - hLen - 1;

    uint8_t maskedSeed[32];
    uint8_t maskedDB[K_LEN];
    memcpy(maskedSeed, em + 1, hLen);
    memcpy(maskedDB, em + 1 + hLen, db_len);

    uint8_t seedMask[32];
    mgf1(maskedDB, db_len, seedMask, hLen);
    uint8_t seed[32];
    for (size_t i = 0; i < hLen; i++) seed[i] = maskedSeed[i] ^ seedMask[i];

    uint8_t dbMask[K_LEN];
    mgf1(seed, hLen, dbMask, db_len);
    uint8_t DB[K_LEN];
    for (size_t i = 0; i < db_len; i++) DB[i] = maskedDB[i] ^ dbMask[i];

    uint8_t err = 0;
    err |= em[0];

    uint8_t lHash[32];
    sha256(label, label_len, lHash);
    for (size_t i = 0; i < hLen; i++) err |= (uint8_t)(lHash[i] ^ DB[i]);

    size_t msg_off = 0;
    uint8_t found = 0;
    uint8_t sep_err = 0;
    for (size_t i = hLen; i < db_len; i++) {
        uint8_t b = DB[i];
        uint8_t is_zero = (uint8_t)(b == 0x00);
        uint8_t is_one = (uint8_t)(b == 0x01);
        uint8_t not_found = (uint8_t)(found ^ 1);
        uint8_t is_sep = not_found & is_one;
        uint8_t is_bad = not_found & (uint8_t)(is_zero ^ 1)
            & (uint8_t)(is_one ^ 1);
        sep_err |= is_bad;
        size_t mask = (size_t)0 - (size_t)is_sep;
        msg_off = (msg_off & ~mask) | (((size_t)(i + 1)) & mask);
        found |= is_sep;
    }
    err |= sep_err;
    err |= (uint8_t)(found ^ 1);

    size_t out_len = db_len - msg_off;
    if (msg_off == 0 || out_len > db_len) out_len = 0;
    for (size_t i = 0; i < out_len; i++) msg[i] = DB[msg_off + i];
    *msg_len = out_len;

    return (err == 0) ? 0 : -1;
}

static int is_prime(const BigInt* n) {
    static const u32 small[] = { 2,3,5,7,11,13,17,19,23,29,31,37 };
    BigInt t;
    for (int i = 0; i < 12; i++) {
        bi_set_u32(&t, small[i]);
        if (bi_cmp(n, &t) == 0) return 1;
        if (n->v[0] % small[i] == 0 && bi_cmp(n, &t) != 0) return 0;
    }
    if ((n->v[0] & 1) == 0) return 0;

    mont_setup(n->v[0]);

    BigInt nm1, one, d;
    bi_set_u32(&one, 1);
    bi_sub(&nm1, n, &one);
    bi_copy(&d, &nm1);
    int s = 0;
    while ((d.v[0] & 1) == 0) { bi_shr1(&d, &d); s++; }

    static const u32 bases[] = { 2,3,5,7,11,13,17,19,23,29,31,37,
                                41,43,47,53,59,61,67,71,73,79,83,89,
                                97,101,103,107,109,113 };
    const int NB = 30;
    u32 is_comp = 0;
    for (int i = 0; i < NB; i++) {
        BigInt a; bi_set_u32(&a, bases[i]);
        if (bi_cmp(&a, n) >= 0) continue;
        BigInt x;
        mont_modexp(&x, &a, &d, n);
        u32 is_one_x = (u32)bi_is_one(&x);
        u32 is_nm1 = (u32)(bi_cmp(&x, &nm1) == 0);
        u32 ok = is_one_x | is_nm1;
        for (int r = 1; r < s; r++) {
            BigInt x2;
            mont_mul(&x2, &x, &x, n);
            bi_copy(&x, &x2);
            is_nm1 = (u32)(bi_cmp(&x, &nm1) == 0);
            ok |= is_nm1;
        }
        is_comp |= (ok ^ 1);
    }
    return (int)(is_comp == 0);
}

static void gen_prime(BigInt* p, int bits) {
    for (int i = 0; i < N_LIMBS; i++) p->v[i] = rng32();
    int high_limb = (bits + 31) / 32;
    for (int i = high_limb; i < N_LIMBS; i++) p->v[i] = 0;
    int rem = bits % 32;
    if (rem) p->v[high_limb - 1] &= ((u32)1 << rem) - 1;
    p->v[(bits - 1) / 32] |= (u32)1 << ((bits - 1) % 32);
    p->v[0] |= 1;
    while (!is_prime(p)) {
        u64 carry = 2;
        for (int i = 0; i < N_LIMBS && carry; i++) {
            u64 t = (u64)p->v[i] + carry;
            p->v[i] = (u32)t;
            carry = t >> 32;
        }
    }
}

static void bi_modinv(BigInt* r, const BigInt* a_in, const BigInt* m) {
    BigInt u, v, x1, x2, one;
    BigInt a;
    bi_copy(&a, a_in);
    while (bi_cmp(&a, m) >= 0) bi_sub(&a, &a, m);
    bi_copy(&u, &a);
    bi_copy(&v, m);
    bi_set_u32(&x1, 1);
    bi_set_u32(&x2, 0);
    bi_set_u32(&one, 1);
    while (!bi_is_zero(&u) && !bi_is_zero(&v)) {
        while ((u.v[0] & 1) == 0) {
            bi_shr1(&u, &u);
            if (x1.v[0] & 1) bi_add(&x1, &x1, m);
            bi_shr1(&x1, &x1);
        }
        while ((v.v[0] & 1) == 0) {
            bi_shr1(&v, &v);
            if (x2.v[0] & 1) bi_add(&x2, &x2, m);
            bi_shr1(&x2, &x2);
        }
        if (bi_cmp(&u, &v) >= 0) {
            bi_sub(&u, &u, &v);
            if (bi_sub_b(&x1, &x1, &x2)) bi_add(&x1, &x1, m);
        }
        else {
            bi_sub(&v, &v, &u);
            if (bi_sub_b(&x2, &x2, &x1)) bi_add(&x2, &x2, m);
        }
    }
    if (bi_is_one(&u)) bi_copy(r, &x1); else bi_copy(r, &x2);
}

struct RSAPublic { BigInt N, e; };
struct RSAPrivate { BigInt N, d, p, q, dp, dq, qinv; };

static void rsa_keygen(RSAPublic* pub, RSAPrivate* priv) {
    BigInt p, q, one, phi;
    bi_set_u32(&one, 1);
    gen_prime(&p, PRIME_BITS);
    gen_prime(&q, PRIME_BITS);
    if (bi_cmp(&p, &q) < 0) { BigInt t = p; p = q; q = t; }

    bi_copy(&pub->N, &p);
    {
        BigInt tmp;
        BigInt N;
        bi_zero(&N);
        for (int i = 0; i < N_LIMBS; i++) {
            u64 carry = 0;
            for (int j = 0; j < N_LIMBS; j++) {
                if (i + j >= N_LIMBS) break;
                u64 t = (u64)N.v[i + j] + (u64)p.v[i] * q.v[j] + carry;
                N.v[i + j] = (u32)t;
                carry = t >> 32;
            }
        }
        bi_copy(&pub->N, &N);
        (void)tmp;
    }

    bi_sub(&phi, &p, &one);
    BigInt qm1;
    bi_sub(&qm1, &q, &one);
    {
        BigInt ph;
        bi_zero(&ph);
        for (int i = 0; i < N_LIMBS; i++) {
            u64 carry = 0;
            for (int j = 0; j < N_LIMBS; j++) {
                if (i + j >= N_LIMBS) break;
                u64 t = (u64)ph.v[i + j] + (u64)phi.v[i] * qm1.v[j] + carry;
                ph.v[i + j] = (u32)t;
                carry = t >> 32;
            }
        }
        bi_copy(&phi, &ph);
    }

    bi_set_u32(&pub->e, 65537);
    bi_modinv(&priv->d, &pub->e, &phi);

    bi_copy(&priv->N, &pub->N);
    bi_copy(&priv->p, &p);
    bi_copy(&priv->q, &q);

    BigInt pm1;
    bi_sub(&pm1, &p, &one);

    {
        BigInt e_full, d;
        bi_zero(&e_full);
        for (int i = 0; i < N_LIMBS; i++) {
            u64 carry = 0;
            for (int j = 0; j < N_LIMBS; j++) {
                if (i + j >= N_LIMBS) break;
                u64 t = (u64)e_full.v[i + j] + (u64)priv->d.v[i] * (u64)1 + carry;
                e_full.v[i + j] = (u32)t;
                carry = t >> 32;
            }
        }
        (void)e_full;
    }

    {
        BigInt qinv;
        bi_modinv(&qinv, &q, &p);
        bi_copy(&priv->qinv, &qinv);
    }

    {
        BigInt pm1_copy, qm1_copy, dpm, dqm;
        bi_copy(&pm1_copy, &pm1);
        bi_copy(&qm1_copy, &qm1);
        (void)dpm; (void)dqm;

        BigInt r;
        bi_copy(&r, &priv->d);
        BigInt qq;
        bi_copy(&qq, &pm1_copy);
        while (bi_cmp(&r, &qq) >= 0) bi_sub(&r, &r, &qq);
        bi_copy(&priv->dp, &r);

        bi_copy(&r, &priv->d);
        BigInt qq2;
        bi_copy(&qq2, &qm1_copy);
        while (bi_cmp(&r, &qq2) >= 0) bi_sub(&r, &r, &qq2);
        bi_copy(&priv->dq, &r);
    }
}

static void rsa_decrypt_crt(BigInt* m, const RSAPrivate* priv, const BigInt* c) {
    BigInt m1, m2, h, diff, borrow_int, tmp;

    mont_modexp(&m1, c, &priv->dp, &priv->p);
    mont_modexp(&m2, c, &priv->dq, &priv->q);

    diff = m1;
    u32 borrow = bi_sub_b(&diff, &diff, &m2);
    bi_set_u32(&borrow_int, borrow);
    BigInt t2;
    bi_copy(&t2, &priv->p);
    for (int i = 0; i < N_LIMBS; i++) {
        u64 carry = 0;
        for (int j = 0; j < N_LIMBS; j++) {
            if (i + j >= N_LIMBS) break;
            u64 t = (u64)tmp.v[i + j] + (u64)borrow_int.v[i] * t2.v[j] + carry;
            tmp.v[i + j] = (u32)t;
            carry = t >> 32;
        }
    }
    bi_add(&diff, &diff, &tmp);

    {
        BigInt qinv_copy;
        bi_copy(&qinv_copy, &priv->qinv);
        mont_setup(priv->p.v[0]);
        BigInt tmp_h;
        mont_from(&tmp_h, &qinv_copy, &priv->p);
        BigInt tmp_d;
        mont_from(&tmp_d, &diff, &priv->p);
        mont_mul(&h, &tmp_h, &tmp_d, &priv->p);
        BigInt one;
        bi_set_u32(&one, 1);
        mont_mul(&tmp_h, &h, &one, &priv->p);
        bi_copy(&h, &tmp_h);
    }

    bi_zero(m);
    for (int i = 0; i < N_LIMBS; i++) {
        u64 carry = 0;
        for (int j = 0; j < N_LIMBS; j++) {
            if (i + j >= N_LIMBS) break;
            u64 t = (u64)m->v[i + j] + (u64)h.v[i] * priv->q.v[j] + carry;
            m->v[i + j] = (u32)t;
            carry = t >> 32;
        }
    }
    bi_add(m, m, &m2);
}

static void rsa_encrypt(BigInt* c, const RSAPublic* pub, const BigInt* m) {
    BigInt e2, mm;
    bi_set_u32(&e2, 65537);
    bi_copy(&mm, m);
    mont_modexp(c, &mm, &e2, &pub->N);
}

static void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++)
        cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
    cout << dec << endl;
}

int main() {
    cout << "===== Laboratory work #2: RSA(4096-cap) + CRT + OAEP + constant-time =====" << endl << endl;

    RSAPublic pub;
    RSAPrivate priv;
    cout << "[RSA Keygen] generating primes (" << PRIME_BITS << " bits each)..." << endl;
    rsa_keygen(&pub, &priv);
    cout << "  done." << endl << endl;

    const char label[] = "";
    const char msg[] = "Hello, RSA+OAEP!";
    size_t msg_len = sizeof(msg) - 1;

    uint8_t seed[HASH_LEN];
    for (int i = 0; i < HASH_LEN; i++) seed[i] = (uint8_t)rng32();

    uint8_t em[K_LEN];
    if (oaep_encode((const uint8_t*)msg, msg_len, (const uint8_t*)label, 0, seed, em) != 0) {
        cout << "OAEP encode failed" << endl;
        return 1;
    }
    cout << "[OAEP encode]" << endl;
    cout << "  msg: " << msg << endl;
    cout << "  EM : "; print_hex(em, K_LEN);
    cout << endl;

    BigInt m, c, m_dec;
    bi_from_bytes(&m, em, K_LEN);
    rsa_encrypt(&c, &pub, &m);

    uint8_t cbytes[N_BYTES];
    bi_to_bytes(&c, cbytes, K_LEN);
    cout << "[RSA encrypt]" << endl;
    cout << "  c  : "; print_hex(cbytes, K_LEN);
    cout << endl;

    rsa_decrypt_crt(&m_dec, &priv, &c);
    uint8_t em2[K_LEN];
    bi_to_bytes(&m_dec, em2, K_LEN);
    cout << "[RSA decrypt (CRT)]" << endl;
    cout << "  EM': "; print_hex(em2, K_LEN);
    cout << "  round-trip: " << (memcmp(em, em2, K_LEN) == 0 ? "OK" : "FAIL") << endl << endl;

    uint8_t out[K_LEN];
    size_t out_len = 0;
    int rc = oaep_decode_ct(em2, (const uint8_t*)label, 0, out, &out_len);
    cout << "[OAEP decode]" << endl;
    if (rc == 0) {
        cout << "  status: OK" << endl;
        cout << "  msg   : ";
        for (size_t i = 0; i < out_len; i++) cout << (char)out[i];
        cout << endl;
    }
    else {
        cout << "  status: FAIL" << endl;
    }
    cout << endl;

    uint8_t em_bad[K_LEN];
    memcpy(em_bad, em2, K_LEN);
    em_bad[K_LEN - 1] ^= 0x01;
    size_t out_len_bad = 0;
    int rc_bad = oaep_decode_ct(em_bad, (const uint8_t*)label, 0, out, &out_len_bad);
    cout << "[OAEP decode, corrupted EM]" << endl;
    cout << "  status: " << (rc_bad == 0 ? "ACCEPTED (bad!)" : "REJECTED (ok)") << endl << endl;

    const int REPS = 2000;
    auto t0 = chrono::high_resolution_clock::now();
    for (int i = 0; i < REPS; i++) oaep_decode_ct(em2, (const uint8_t*)label, 0, out, &out_len);
    auto t1 = chrono::high_resolution_clock::now();
    for (int i = 0; i < REPS; i++) oaep_decode_ct(em_bad, (const uint8_t*)label, 0, out, &out_len_bad);
    auto t2 = chrono::high_resolution_clock::now();

    double ns_valid = (double)chrono::duration_cast<chrono::nanoseconds>(t1 - t0).count() / REPS;
    double ns_bad = (double)chrono::duration_cast<chrono::nanoseconds>(t2 - t1).count() / REPS;
    cout << "[Constant-time measurement]" << endl;
    cout << "  avg ns, valid EM    : " << ns_valid << endl;
    cout << "  avg ns, corrupted EM: " << ns_bad << endl;
    cout << endl;

    return 0;
}