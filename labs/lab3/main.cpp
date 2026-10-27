#include <cstdint>
#include <cstdio>
#include <cstring>
#include <array>
#include <string>

static constexpr int NW = 4;

struct U256 {
    uint64_t w[NW];
};

static inline uint64_t add64(uint64_t a, uint64_t b, uint64_t& carry) {
    uint64_t s = a + b;
    uint64_t c1 = (s < a) ? 1ULL : 0ULL;
    uint64_t s2 = s + carry;
    uint64_t c2 = (s2 < s) ? 1ULL : 0ULL;
    carry = c1 | c2;
    return s2;
}

static inline uint64_t sub64(uint64_t a, uint64_t b, uint64_t& borrow) {
    uint64_t d = a - b;
    uint64_t b1 = (a < b) ? 1ULL : 0ULL;
    uint64_t d2 = d - borrow;
    uint64_t b2 = (d < borrow) ? 1ULL : 0ULL;
    borrow = b1 | b2;
    return d2;
}

static inline int cmp_u256(const U256& a, const U256& b) {
    uint64_t gt = 0, lt = 0;
    for (int i = NW - 1; i >= 0; --i) {
        uint64_t ai = a.w[i], bi = b.w[i];
        uint64_t eq_so_far = (gt | lt) ^ 1ULL;
        uint64_t g = (ai > bi) ? 1ULL : 0ULL;
        uint64_t l = (ai < bi) ? 1ULL : 0ULL;
        gt |= g & eq_so_far;
        lt |= l & eq_so_far;
    }
    return (int)(gt - lt);
}

static inline bool eq_u256(const U256& a, const U256& b) {
    uint64_t acc = 0;
    for (int i = 0; i < NW; ++i) acc |= (a.w[i] ^ b.w[i]);
    return acc == 0;
}

static inline bool is_zero(const U256& a) {
    uint64_t acc = 0;
    for (int i = 0; i < NW; ++i) acc |= a.w[i];
    return acc == 0;
}

static inline bool is_one(const U256& a) {
    return a.w[0] == 1 && a.w[1] == 0 && a.w[2] == 0 && a.w[3] == 0;
}

static inline U256 zero_u256() { U256 r; for (int i=0;i<NW;++i) r.w[i]=0; return r; }
static inline U256 one_u256()  { U256 r = zero_u256(); r.w[0]=1; return r; }

static inline void set_u64(U256& a, uint64_t v) { a = zero_u256(); a.w[0]=v; }
static inline uint64_t get_bit(const U256& a, int bit) {
    return (a.w[bit>>6] >> (bit & 63)) & 1ULL;
}
static inline int bitlen(const U256& a) {
    for (int i = NW - 1; i >= 0; --i)
        if (a.w[i]) {
            int b = 0; uint64_t x = a.w[i];
            while (x) { ++b; x >>= 1; }
            return i*64 + b;
        }
    return 0;
}

static inline U256 add_u256(const U256& a, const U256& b, uint64_t& carry) {
    U256 r; carry = 0;
    for (int i = 0; i < NW; ++i) r.w[i] = add64(a.w[i], b.w[i], carry);
    return r;
}
static inline U256 sub_u256(const U256& a, const U256& b, uint64_t& borrow) {
    U256 r; borrow = 0;
    for (int i = 0; i < NW; ++i) r.w[i] = sub64(a.w[i], b.w[i], borrow);
    return r;
}

static inline U256 shl1(const U256& a, uint64_t& carry_out) {
    U256 r; carry_out = a.w[NW-1] >> 63;
    for (int i = NW-1; i > 0; --i)
        r.w[i] = (a.w[i] << 1) | (a.w[i-1] >> 63);
    r.w[0] = a.w[0] << 1;
    return r;
}
static inline U256 shr1(const U256& a, uint64_t& carry_out) {
    U256 r; carry_out = a.w[0] & 1ULL;
    for (int i = 0; i < NW-1; ++i)
        r.w[i] = (a.w[i] >> 1) | (a.w[i+1] << 63);
    r.w[NW-1] = a.w[NW-1] >> 1;
    return r;
}

static U256 g_p;
static U256 g_a;

static U256 mod_reduce(U256 x) {
    for (int it = 0; it < 4; ++it) {
        uint64_t borrow = 0;
        U256 d = sub_u256(x, g_p, borrow);
        uint64_t mask = 0ULL - (borrow ^ 1ULL);
        for (int i = 0; i < NW; ++i)
            x.w[i] = (d.w[i] & mask) | (x.w[i] & ~mask);
    }
    return x;
}

static inline U256 mod_add(const U256& a, const U256& b) {
    uint64_t carry;
    U256 s = add_u256(a, b, carry);
    uint64_t borrow = 0;
    U256 d = sub_u256(s, g_p, borrow);
    bool ge = (carry != 0) || (borrow == 0);
    uint64_t mask = 0ULL - (uint64_t)ge;
    U256 r;
    for (int i = 0; i < NW; ++i)
        r.w[i] = (d.w[i] & mask) | (s.w[i] & ~mask);
    return r;
}

static inline U256 mod_sub(const U256& a, const U256& b) {
    uint64_t borrow;
    U256 d = sub_u256(a, b, borrow);
    if (borrow) {
        uint64_t c;
        d = add_u256(d, g_p, c);
    }
    return d;
}

static inline void mul64x64(uint64_t a, uint64_t b, uint64_t& lo, uint64_t& hi) {
    uint64_t a0 = a & 0xFFFFFFFFULL, a1 = a >> 32;
    uint64_t b0 = b & 0xFFFFFFFFULL, b1 = b >> 32;
    uint64_t p00 = a0 * b0;
    uint64_t p01 = a0 * b1;
    uint64_t p10 = a1 * b0;
    uint64_t p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & 0xFFFFFFFFULL) + (p10 & 0xFFFFFFFFULL);
    lo = (p00 & 0xFFFFFFFFULL) | (mid << 32);
    hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}

static inline void mul_u256_full(const U256& a, const U256& b, uint64_t r[8]) {
    for (int i = 0; i < 8; ++i) r[i] = 0;
    for (int i = 0; i < NW; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < NW; ++j) {
            uint64_t lo, hi;
            mul64x64(a.w[i], b.w[j], lo, hi);
            uint64_t c1 = 0;
            uint64_t s1 = add64(r[i+j], lo, c1);
            uint64_t c2 = 0;
            uint64_t s2 = add64(s1, carry, c2);
            r[i+j] = s2;
            carry = hi + c1 + c2;
        }
        r[i + NW] += carry;
    }
}

static U256 mod_mul(const U256& a, const U256& b) {
    uint64_t prod[8];
    mul_u256_full(a, b, prod);
    U256 lo, hi;
    for (int i = 0; i < NW; ++i) { lo.w[i] = prod[i]; hi.w[i] = prod[i+NW]; }
    static U256 R256; static bool R_init = false;
    if (!R_init) {
        uint64_t b0 = 1;
        U256 z = zero_u256();
        U256 diff = sub_u256(z, g_p, b0);
        R256 = diff;
        R_init = true;
    }
    U256 H = mod_reduce(hi);
    U256 T = zero_u256();
    U256 acc = H;
    for (int bit = 0; bit < 256; ++bit) {
        if (get_bit(R256, bit)) T = mod_add(T, acc);
        acc = mod_add(acc, acc);
    }
    return mod_add(lo, T);
}

static inline U256 mod_sqr(const U256& a) { return mod_mul(a, a); }

static U256 mod_pow(const U256& a, const U256& e) {
    U256 result = one_u256();
    U256 base = mod_reduce(a);
    int n = bitlen(e);
    for (int i = 0; i < n; ++i) {
        if (get_bit(e, i)) result = mod_mul(result, base);
        base = mod_sqr(base);
    }
    return result;
}

static U256 mod_inv(const U256& a) {
    U256 e = g_p;
    U256 two; set_u64(two, 2);
    uint64_t borrow; e = sub_u256(e, two, borrow);
    return mod_pow(a, e);
}

static U256 from_hex(const char* s) {
    U256 r = zero_u256();
    size_t n = strlen(s);
    int word = 0;
    int i = (int)n - 1;
    while (i >= 0 && word < NW) {
        uint64_t acc = 0;
        int cnt = 0;
        while (i >= 0 && cnt < 16) {
            char c = s[i];
            uint64_t v;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
            else { --i; continue; }
            acc |= v << (4 * cnt);
            ++cnt; --i;
        }
        r.w[word++] = acc;
    }
    return r;
}

static void print_hex(const char* label, const U256& a) {
    printf("%s = 0x", label);
    for (int i = NW-1; i >= 0; --i) printf("%016llx", (unsigned long long)a.w[i]);
    printf("\n");
}

struct Point {
    U256 X, Y, Z;
};

static Point point_infinity() {
    Point p; p.X = one_u256(); p.Y = one_u256(); p.Z = zero_u256();
    return p;
}
static bool is_infinity(const Point& p) { return is_zero(p.Z); }

static Point point_from_affine(const U256& x, const U256& y) {
    Point p; p.X = x; p.Y = y; p.Z = one_u256(); return p;
}

static bool point_eq_ct(const Point& a, const Point& b) {
    U256 z2a = mod_sqr(a.Z), z2b = mod_sqr(b.Z);
    U256 z3a = mod_mul(z2a, a.Z), z3b = mod_mul(z2b, b.Z);
    U256 lx = mod_mul(a.X, z2b);
    U256 rx = mod_mul(b.X, z2a);
    U256 ly = mod_mul(a.Y, z3b);
    U256 ry = mod_mul(b.Y, z3a);
    uint64_t acc = 0;
    for (int i = 0; i < NW; ++i) acc |= (lx.w[i] ^ rx.w[i]);
    for (int i = 0; i < NW; ++i) acc |= (ly.w[i] ^ ry.w[i]);
    bool xy_eq = (acc == 0);
    bool a_inf = is_zero(a.Z), b_inf = is_zero(b.Z);
    uint64_t same_inf = (uint64_t)(a_inf == b_inf);
    uint64_t both_inf  = (uint64_t)(a_inf & b_inf);
    return both_inf || (same_inf && xy_eq);
}

static Point point_double(const Point& P) {
    if (is_infinity(P)) return P;
    U256 Y2 = mod_sqr(P.Y);
    U256 four; set_u64(four, 4);
    U256 three; set_u64(three, 3);
    U256 two; set_u64(two, 2);
    U256 eight; set_u64(eight, 8);
    U256 S  = mod_mul(mod_mul(P.X, Y2), four);
    U256 Z2 = mod_sqr(P.Z);
    U256 Z4 = mod_sqr(Z2);
    U256 M  = mod_add(mod_mul(three, mod_sqr(P.X)), mod_mul(g_a, Z4));
    U256 X3 = mod_sub(mod_sqr(M), mod_add(S, S));
    U256 Y4 = mod_sqr(Y2);
    U256 Y3 = mod_sub(mod_mul(M, mod_sub(S, X3)), mod_mul(eight, Y4));
    U256 Z3 = mod_mul(mod_mul(two, P.Y), P.Z);
    Point R; R.X = X3; R.Y = Y3; R.Z = Z3; return R;
}

static Point point_add(const Point& P1, const Point& P2) {
    if (is_infinity(P1)) return P2;
    if (is_infinity(P2)) return P1;
    U256 Z1Z1 = mod_sqr(P1.Z);
    U256 Z2Z2 = mod_sqr(P2.Z);
    U256 U1 = mod_mul(P1.X, Z2Z2);
    U256 U2 = mod_mul(P2.X, Z1Z1);
    U256 Z1Z1Z1 = mod_mul(Z1Z1, P1.Z);
    U256 Z2Z2Z2 = mod_mul(Z2Z2, P2.Z);
    U256 S1 = mod_mul(P1.Y, Z2Z2Z2);
    U256 S2 = mod_mul(P2.Y, Z1Z1Z1);
    U256 H  = mod_sub(U2, U1);
    U256 R  = mod_sub(S2, S1);
    if (is_zero(H)) {
        if (is_zero(R)) return point_double(P1);
        return point_infinity();
    }
    U256 H2 = mod_sqr(H);
    U256 H3 = mod_mul(H2, H);
    U256 U1H2 = mod_mul(U1, H2);
    U256 X3 = mod_sub(mod_sub(mod_sqr(R), H3), mod_add(U1H2, U1H2));
    U256 Y3 = mod_sub(mod_mul(R, mod_sub(U1H2, X3)), mod_mul(S1, H3));
    U256 Z3 = mod_mul(mod_mul(H, P1.Z), P2.Z);
    Point R3; R3.X = X3; R3.Y = Y3; R3.Z = Z3; return R3;
}

static void to_affine(const Point& P, U256& x, U256& y) {
    if (is_infinity(P)) { x = zero_u256(); y = zero_u256(); return; }
    U256 zi  = mod_inv(P.Z);
    U256 zi2 = mod_sqr(zi);
    U256 zi3 = mod_mul(zi2, zi);
    x = mod_mul(P.X, zi2);
    y = mod_mul(P.Y, zi3);
}

static inline void cswap_point(Point& a, Point& b, uint64_t bit) {
    uint64_t mask = 0ULL - bit;
    for (int i = 0; i < NW; ++i) {
        uint64_t t = mask & (a.X.w[i] ^ b.X.w[i]);
        a.X.w[i] ^= t; b.X.w[i] ^= t;
        t = mask & (a.Y.w[i] ^ b.Y.w[i]);
        a.Y.w[i] ^= t; b.Y.w[i] ^= t;
        t = mask & (a.Z.w[i] ^ b.Z.w[i]);
        a.Z.w[i] ^= t; b.Z.w[i] ^= t;
    }
}

static Point scalar_mul_ct(const U256& k, const Point& P) {
    Point R0 = point_infinity();
    Point R1 = P;
    int n = bitlen(k);
    for (int i = n - 1; i >= 0; --i) {
        uint64_t bit = get_bit(k, i);
        cswap_point(R0, R1, bit);
        R1 = point_add(R0, R1);
        R0 = point_double(R0);
        cswap_point(R0, R1, bit);
    }
    return R0;
}

static U256 g_q;
static Point g_G;

static U256 mod_q(const U256& x) {
    U256 saved = g_p; g_p = g_q;
    U256 r = mod_reduce(x);
    g_p = saved;
    return r;
}

static uint64_t rng_state = 0x123456789ABCDEF0ULL;
static uint64_t xorshift64() {
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng_state = x; return x;
}
static U256 random_scalar_mod_q() {
    U256 r;
    for (int i = 0; i < NW; ++i) r.w[i] = xorshift64();
    r = mod_q(r);
    if (is_zero(r)) r = one_u256();
    return r;
}

struct Signature { U256 r, s; bool ok; };

static U256 add_mod_q(const U256& a, const U256& b) {
    U256 saved = g_p; g_p = g_q;
    U256 r = mod_add(a, b);
    g_p = saved;
    return r;
}

static Signature gost_sign(const U256& e, const U256& d) {
    Signature sig; sig.ok = false;
    for (int attempt = 0; attempt < 100; ++attempt) {
        U256 k = random_scalar_mod_q();
        Point C = scalar_mul_ct(k, g_G);
        U256 xc, yc; to_affine(C, xc, yc);
        U256 r = mod_q(xc);
        if (is_zero(r)) continue;
        U256 rd = mod_q(mod_mul(r, d));
        U256 ke = mod_q(mod_mul(k, e));
        U256 s  = mod_q(add_mod_q(rd, ke));
        if (is_zero(s)) continue;
        sig.r = r; sig.s = s; sig.ok = true;
        return sig;
    }
    return sig;
}

static bool gost_verify(const U256& e, const Signature& sig, const Point& Q) {
    if (is_zero(sig.r) || is_zero(sig.s)) return false;
    U256 zero = zero_u256();
    if (cmp_u256(sig.r, zero) <= 0) return false;
    if (cmp_u256(sig.s, zero) <= 0) return false;
    if (cmp_u256(sig.r, g_q) >= 0) return false;
    if (cmp_u256(sig.s, g_q) >= 0) return false;

    U256 saved = g_p; g_p = g_q;
    U256 v = mod_inv(e);
    g_p = saved;
    U256 sv = mod_mul(sig.s, v);
    U256 z1 = mod_q(sv);
    U256 rv = mod_mul(sig.r, v);
    U256 z2 = mod_q(mod_sub(g_q, rv));
    Point C1 = scalar_mul_ct(z1, g_G);
    Point C2 = scalar_mul_ct(z2, Q);
    Point C  = point_add(C1, C2);
    U256 xc, yc; to_affine(C, xc, yc);
    U256 R = mod_q(xc);
    return eq_u256(R, sig.r);
}

static U256 toy_hash(const uint8_t* data, size_t len) {
    U256 h = zero_u256();
    h.w[0] = 0xcbf29ce484222325ULL;
    h.w[1] = 0x100000001b3ULL;
    for (size_t i = 0; i < len; ++i) {
        h.w[0] ^= data[i];
        h.w[0] *= 0x100000001b3ULL;
        h.w[1] += h.w[0] ^ (h.w[0] >> 17);
        h.w[2] = (h.w[2] << 1) | (h.w[1] >> 63);
    }
    return h;
}

static void init_curve() {
    g_p = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    g_a = zero_u256();
    g_q = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    U256 gx = from_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    U256 gy = from_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    g_G = point_from_affine(gx, gy);
}

static bool point_on_curve(const U256& x, const U256& y) {
    U256 lhs = mod_sqr(y);
    U256 x3  = mod_mul(mod_sqr(x), x);
    U256 ax  = mod_mul(g_a, x);
    U256 seven; set_u64(seven, 7);
    U256 rhs = mod_add(mod_add(x3, ax), seven);
    return eq_u256(lhs, rhs);
}

int main() {
    init_curve();

    U256 gx, gy; to_affine(g_G, gx, gy);
    printf("== Параметры кривой ==\n");
    print_hex("p", g_p);
    print_hex("q", g_q);
    print_hex("Gx", gx);
    print_hex("Gy", gy);
    printf("G on curve: %s\n\n", point_on_curve(gx, gy) ? "yes" : "no");

    printf("== Constant-time сравнение точек ==\n");
    U256 one; set_u64(one, 1);
    U256 two; set_u64(two, 2);
    Point P1 = scalar_mul_ct(one, g_G);
    Point P2 = scalar_mul_ct(one, g_G);
    Point P3 = scalar_mul_ct(two, g_G);
    printf("P1 == P2 : %s\n", point_eq_ct(P1, P2) ? "true" : "false");
    printf("P1 == P3 : %s\n\n", point_eq_ct(P1, P3) ? "true" : "false");

    printf("== ECDH ==\n");
    U256 dA = random_scalar_mod_q();
    U256 dB = random_scalar_mod_q();
    Point QA = scalar_mul_ct(dA, g_G);
    Point QB = scalar_mul_ct(dB, g_G);
    Point SA = scalar_mul_ct(dA, QB);
    Point SB = scalar_mul_ct(dB, QA);
    U256 sax, say, sbx, sby;
    to_affine(SA, sax, say); to_affine(SB, sbx, sby);
    print_hex("SharedA.x", sax);
    print_hex("SharedB.x", sbx);
    printf("ECDH match: %s\n\n", eq_u256(sax, sbx) ? "yes" : "no");

    printf("== ГОСТ Р 34.10-2012 ==\n");
    U256 d = random_scalar_mod_q();
    Point Q = scalar_mul_ct(d, g_G);
    const char* msg = "test message for lab3";
    U256 e = mod_q(toy_hash((const uint8_t*)msg, strlen(msg)));
    print_hex("e", e);
    Signature sig = gost_sign(e, d);
    print_hex("r", sig.r);
    print_hex("s", sig.s);
    printf("Verify correct: %s\n", gost_verify(e, sig, Q) ? "true" : "false");

    Signature bad = sig;
    bad.s.w[0] ^= 1ULL;
    printf("Verify corrupted s: %s\n", gost_verify(e, bad, Q) ? "true" : "false");

    return 0;
}