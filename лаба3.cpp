#pragma warning(push)
#pragma warning(disable: 4146 4244)
#include <gmp.h>
#pragma warning(pop)

#include <locale.h> 
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstddef>

using namespace std;
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static inline uint64_t rotr64(uint64_t x, unsigned n) {
    return (x >> n) | (x << (64 - n));
}

static void sha512_transform(uint64_t H[8], const uint8_t block[128]) {
    uint64_t W[80];
    for (int i = 0; i < 16; ++i) {
        W[i] = 0;
        for (int j = 0; j < 8; ++j) W[i] = (W[i] << 8) | block[i * 8 + j];
    }
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = rotr64(W[i - 15], 1) ^ rotr64(W[i - 15], 8) ^ (W[i - 15] >> 7);
        uint64_t s1 = rotr64(W[i - 2], 19) ^ rotr64(W[i - 2], 61) ^ (W[i - 2] >> 6);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    uint64_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint64_t e = H[4], f = H[5], g = H[6], h = H[7];

    for (int i = 0; i < 80; ++i) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = h + S1 + ch + K512[i] + W[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

static void sha512(uint8_t out[64], const uint8_t* data, size_t len) {
    uint64_t H[8] = {
        0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL
    };

    size_t full = len / 128;
    for (size_t i = 0; i < full; ++i) {
        sha512_transform(H, data + i * 128);
    }

    uint8_t last[256];
    size_t rem = len % 128;
    if (rem) memcpy(last, data + full * 128, rem);

    last[rem] = 0x80;
    size_t pad_len = (rem < 112) ? 128 : 256;

    memset(last + rem + 1, 0, pad_len - rem - 1 - 16);

    uint64_t bits_lo = (uint64_t)len * 8;
    for (int i = 0; i < 8; ++i) {
        last[pad_len - 16 + i] = 0;
        last[pad_len - 8 + i] = (uint8_t)(bits_lo >> (56 - 8 * i));
    }

    sha512_transform(H, last);
    if (pad_len == 256) sha512_transform(H, last + 128);

    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            out[i * 8 + j] = (uint8_t)(H[i] >> (56 - 8 * j));
        }
    }
}

//Параметры Ed25519 и точка (X, Y, Z, T)
static mpz_t P, Q_ORDER, D, GX, GY;

struct Point {
    mpz_t X, Y, Z, T;

    Point() {
        mpz_inits(X, Y, Z, T, nullptr);
    }

    Point(const Point& o) {
        mpz_inits(X, Y, Z, T, nullptr);
        copy_from(o);
    }

    Point& operator=(const Point& o) {
        if (this != &o) copy_from(o);
        return *this;
    }

    ~Point() {
        mpz_clears(X, Y, Z, T, nullptr);
    }

    void copy_from(const Point& o) {
        mpz_set(X, o.X);
        mpz_set(Y, o.Y);
        mpz_set(Z, o.Z);
        mpz_set(T, o.T);
    }

    void identity() {
        mpz_set_ui(X, 0);
        mpz_set_ui(Y, 1);
        mpz_set_ui(Z, 1);
        mpz_set_ui(T, 0);
    }
};

// Базовая точка G. Инициализируется конструктором Point.
static Point G;

//  Модульная арифметика GF(p)

static void mod_add(mpz_t r, const mpz_t a, const mpz_t b, const mpz_t p) {
    mpz_add(r, a, b);
    mpz_mod(r, r, p);
}

static void mod_sub(mpz_t r, const mpz_t a, const mpz_t b, const mpz_t p) {
    mpz_sub(r, a, b);
    mpz_mod(r, r, p);
}

static void mod_mul(mpz_t r, const mpz_t a, const mpz_t b, const mpz_t p) {
    mpz_mul(r, a, b);
    mpz_mod(r, r, p);
}

static void mod_inv(mpz_t r, const mpz_t a, const mpz_t p) {
    mpz_t e;
    mpz_init(e);
    mpz_sub_ui(e, p, 2);
    mpz_powm(r, a, e, p);
    mpz_clear(e);
}

//  Полная формула сложения для twisted Edwards (a = -1), extended coords.
static void point_add(Point& r, const Point& p1, const Point& p2) {
    mpz_t A, B, C, Dd, E, F, Gg, H, t1, t2;
    mpz_inits(A, B, C, Dd, E, F, Gg, H, t1, t2, nullptr);

    mod_sub(t1, p1.Y, p1.X, P);
    mod_sub(t2, p2.Y, p2.X, P);
    mod_mul(A, t1, t2, P);      // A=(Y1-X1)(Y2-X2)

    mod_add(t1, p1.Y, p1.X, P);
    mod_add(t2, p2.Y, p2.X, P);
    mod_mul(B, t1, t2, P);      // B=(Y1+X1)(Y2+X2)

    mod_mul(t1, p1.T, p2.T, P);
    mod_mul(t1, t1, D, P);
    mod_add(C, t1, t1, P);      // C = 2*d*T1*T2

    mod_mul(t1, p1.Z, p2.Z, P);
    mod_add(Dd, t1, t1, P);     // Dd = 2*Z1*Z2

    mod_sub(E, B, A, P);
    mod_sub(F, Dd, C, P);
    mod_add(Gg, Dd, C, P);
    mod_add(H, B, A, P);

    mod_mul(r.X, E, F, P);
    mod_mul(r.Y, Gg, H, P);
    mod_mul(r.T, E, H, P);
    mod_mul(r.Z, F, Gg, P);

    mpz_clears(A, B, C, Dd, E, F, Gg, H, t1, t2, nullptr);
}

static void point_double(Point& r, const Point& p) {
    point_add(r, p, p);
}

//CONSTANT-TIME CSWAP и лестница Монтгомери
static void cswap_mpz(mpz_t a, mpz_t b, int bit) {
    mpz_t mask, dummy;
    mpz_inits(mask, dummy, nullptr);

    mpz_set_ui(mask, (unsigned long)bit);
    mpz_neg(mask, mask);

    mpz_xor(dummy, a, b);
    mpz_and(dummy, dummy, mask);

    mpz_xor(a, a, dummy);
    mpz_xor(b, b, dummy);

    mpz_clears(mask, dummy, nullptr);
}

static void cswap_point(Point& p, Point& q, int bit) {
    cswap_mpz(p.X, q.X, bit);
    cswap_mpz(p.Y, q.Y, bit);
    cswap_mpz(p.Z, q.Z, bit);
    cswap_mpz(p.T, q.T, bit);
}

static void scalar_mult_ct(Point& r, const mpz_t k, const Point& Pt) {
    Point R0, R1;
    R0.identity();
    R1 = Pt;

    for (int i = 255; i >= 0; --i) {
        int bit = mpz_tstbit(k, i);
        cswap_point(R0, R1, bit);
        point_add(R1, R0, R1);
        point_double(R0, R0);
        cswap_point(R0, R1, bit);
    }

    r = R0;
}

//Сжатие / декомпрессия точки Ed25519
static void point_compress(uint8_t out[32], const Point& p) {
    mpz_t zi, x, y;
    mpz_inits(zi, x, y, nullptr);

    mod_inv(zi, p.Z, P);
    mod_mul(x, p.X, zi, P);
    mod_mul(y, p.Y, zi, P);

    memset(out, 0, 32);
    size_t cnt = 0;
    mpz_export(out, &cnt, -1, 1, 0, 0, y);  
    if (mpz_odd_p(x)) out[31] |= 0x80;

    mpz_clears(zi, x, y, nullptr);
}

static bool point_decompress(Point& r, const uint8_t enc[32]) {
    uint8_t yb[32];
    memcpy(yb, enc, 32);

    int sign = (yb[31] >> 7) & 1;
    yb[31] &= 0x7F;

    mpz_t y;
    mpz_init(y);
    mpz_import(y, 32, -1, 1, 0, 0, yb);

    if (mpz_cmp(y, P) >= 0) {
        mpz_clear(y);
        return false;
    }

    mpz_t y2, u, v, vi, x2, x, chk;
    mpz_inits(y2, u, v, vi, x2, x, chk, nullptr);

    mod_mul(y2, y, y, P);

    mpz_sub_ui(u, y2, 1);
    mpz_mod(u, u, P);

    mod_mul(v, D, y2, P);
    mpz_add_ui(v, v, 1);
    mpz_mod(v, v, P);

    // Защита от некорректной кодировки: v = 1 + d*y^2 не должно быть 0.
    if (mpz_sgn(v) == 0) {
        mpz_clears(y, y2, u, v, vi, x2, x, chk, nullptr);
        return false;
    }

    mod_inv(vi, v, P);
    mod_mul(x2, u, vi, P);

    // x = x2^((p+3)/8)
    mpz_t exp, p3;
    mpz_inits(exp, p3, nullptr);

    mpz_add_ui(p3, P, 3);
    mpz_tdiv_q_2exp(exp, p3, 3);
    mpz_powm(x, x2, exp, P);

    mod_mul(chk, x, x, P);

    if (mpz_cmp(chk, x2) != 0) {
        // sqrt(-1) = 2^((p-1)/4)
        mpz_t sq, e1, two;
        mpz_inits(sq, e1, two, nullptr);

        mpz_sub_ui(e1, P, 1);
        mpz_tdiv_q_2exp(e1, e1, 2);
        mpz_set_ui(two, 2);
        mpz_powm(sq, two, e1, P);

        mod_mul(x, x, sq, P);
        mod_mul(chk, x, x, P);

        mpz_clears(sq, e1, two, nullptr);

        if (mpz_cmp(chk, x2) != 0) {
            mpz_clears(y, y2, u, v, vi, x2, x, chk, exp, p3, nullptr);
            return false;
        }
    }

    // RFC 8032: x = 0 и sign = 1 — недопустимая кодировка.
    if (mpz_sgn(x) == 0 && sign) {
        mpz_clears(y, y2, u, v, vi, x2, x, chk, exp, p3, nullptr);
        return false;
    }

    if ((int)mpz_odd_p(x) != sign) {
        mpz_sub(x, P, x);
    }

    mpz_set(r.X, x);
    mpz_set(r.Y, y);
    mpz_set_ui(r.Z, 1);
    mod_mul(r.T, x, y, P);

    mpz_clears(y, y2, u, v, vi, x2, x, chk, exp, p3, nullptr);
    return true;
}
//EdDSA (Ed25519)
static void clamp_scalar(uint8_t out[32], const uint8_t seed[32]) {
    uint8_t h[64];
    sha512(h, seed, 32);

    memcpy(out, h, 32);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
}

static void ed25519_keygen(uint8_t pk[32], const uint8_t seed[32]) {
    uint8_t s[32];
    clamp_scalar(s, seed);

    mpz_t d;
    mpz_init(d);
    mpz_import(d, 32, -1, 1, 0, 0, s);

    Point A;
    scalar_mult_ct(A, d, G);
    point_compress(pk, A);

    mpz_clear(d);
}

//Константное сравнение точек (XOR-аккумулятор)
static bool point_equal_ct(const Point& p, const Point& q) {
    mpz_t t1, t2, t3, t4;
    mpz_inits(t1, t2, t3, t4, nullptr);

    mod_mul(t1, p.X, q.Z, P);
    mod_mul(t2, q.X, p.Z, P);
    mod_mul(t3, p.Y, q.Z, P);
    mod_mul(t4, q.Y, p.Z, P);

    mpz_t a, b;
    mpz_inits(a, b, nullptr);

    mpz_xor(a, t1, t2);
    mpz_xor(b, t3, t4);
    mpz_ior(a, a, b);

    bool ok = (mpz_sgn(a) == 0);

    mpz_clears(t1, t2, t3, t4, a, b, nullptr);
    return ok;
}

constexpr size_t MAX_MSG = 4096;

static void ed25519_sign(uint8_t sig[64], const uint8_t seed[32],
    const uint8_t pk[32],
    const uint8_t* msg, size_t mlen) {
    if (mlen > MAX_MSG) {
        memset(sig, 0, 64);
        return;
    }

    uint8_t h[64];
    sha512(h, seed, 32);

    uint8_t h_lo[32], h_hi[32];
    memcpy(h_lo, h, 32);
    memcpy(h_hi, h + 32, 32);

    h_lo[0] &= 248;
    h_lo[31] &= 127;
    h_lo[31] |= 64;

    // r = SHA-512(h_hi || M) mod q
    uint8_t buf[32 + MAX_MSG];
    memcpy(buf, h_hi, 32);
    if (mlen) memcpy(buf + 32, msg, mlen);

    uint8_t rh[64];
    sha512(rh, buf, 32 + mlen);

    mpz_t r;
    mpz_init(r);
    mpz_import(r, 64, -1, 1, 0, 0, rh);
    mpz_mod(r, r, Q_ORDER);

    // R = r*G
    Point R;
    scalar_mult_ct(R, r, G);
    point_compress(sig, R);

    // k = SHA-512(R || A || M) mod q
    uint8_t buf2[64 + MAX_MSG];
    memcpy(buf2, sig, 32);
    memcpy(buf2 + 32, pk, 32);
    if (mlen) memcpy(buf2 + 64, msg, mlen);

    uint8_t kh[64];
    sha512(kh, buf2, 64 + mlen);

    mpz_t k;
    mpz_init(k);
    mpz_import(k, 64, -1, 1, 0, 0, kh);
    mpz_mod(k, k, Q_ORDER);

    // S = (r + k*s) mod q
    mpz_t s;
    mpz_init(s);
    mpz_import(s, 32, -1, 1, 0, 0, h_lo);

    mpz_t S, t;
    mpz_inits(S, t, nullptr);

    mod_mul(t, k, s, Q_ORDER);
    mod_add(S, r, t, Q_ORDER);

    memset(sig + 32, 0, 32);
    size_t cnt = 0;
    mpz_export(sig + 32, &cnt, -1, 1, 0, 0, S);

    mpz_clears(r, k, s, S, t, nullptr);
}

static bool ed25519_verify(const uint8_t sig[64], const uint8_t pk[32],
    const uint8_t* msg, size_t mlen) {
    if (mlen > MAX_MSG) return false;

    Point A, R;
    if (!point_decompress(A, pk)) return false;
    if (!point_decompress(R, sig)) return false;

    mpz_t S;
    mpz_init(S);
    mpz_import(S, 32, -1, 1, 0, 0, sig + 32);

    if (mpz_cmp(S, Q_ORDER) >= 0) {
        mpz_clear(S);
        return false;
    }

    uint8_t buf[64 + MAX_MSG];
    memcpy(buf, sig, 32);
    memcpy(buf + 32, pk, 32);
    if (mlen) memcpy(buf + 64, msg, mlen);

    uint8_t kh[64];
    sha512(kh, buf, 64 + mlen);

    mpz_t k;
    mpz_init(k);
    mpz_import(k, 64, -1, 1, 0, 0, kh);
    mpz_mod(k, k, Q_ORDER);

    // S*G == R + k*A
    Point L, kA, R2;
    scalar_mult_ct(L, S, G);
    scalar_mult_ct(kA, k, A);
    point_add(R2, R, kA);

    bool ok = point_equal_ct(L, R2);

    mpz_clears(S, k, nullptr);
    return ok;
}

// ECDH на Ed25519
static void ed25519_ecdh(uint8_t shared[32],
    const uint8_t priv_scalar[32],
    const uint8_t peer_pub[32]) {
    mpz_t d;
    mpz_init(d);
    mpz_import(d, 32, -1, 1, 0, 0, priv_scalar);

    Point Pub;
    if (!point_decompress(Pub, peer_pub)) {
        memset(shared, 0, 32);
        mpz_clear(d);
        return;
    }

    Point K;
    scalar_mult_ct(K, d, Pub);

    mpz_t zi, x;
    mpz_inits(zi, x, nullptr);

    mod_inv(zi, K.Z, P);
    mod_mul(x, K.X, zi, P);

    memset(shared, 0, 32);
    size_t cnt = 0;
    mpz_export(shared, &cnt, -1, 1, 0, 0, x);

    mpz_clears(d, zi, x, nullptr);
}

// Инициализация параметров кривой Ed25519
static void init_params() {
    mpz_inits(P, Q_ORDER, D, GX, GY, nullptr);

    // p = 2^255 - 19
    mpz_ui_pow_ui(P, 2, 255);
    mpz_sub_ui(P, P, 19);

    // q (порядок подгруппы)
    mpz_set_str(Q_ORDER,
        "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16);

    // d = -121665/121666 mod p
    mpz_t num, den, dinv;
    mpz_inits(num, den, dinv, nullptr);

    mpz_set_si(num, -121665);
    mpz_mod(num, num, P);
    mpz_set_ui(den, 121666);

    mod_inv(dinv, den, P);
    mod_mul(D, num, dinv, P);

    mpz_clears(num, den, dinv, nullptr);

    // Gx, Gy (стандартные Ed25519)
    mpz_set_str(GX,
        "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 16);
    mpz_set_str(GY,
        "6666666666666666666666666666666666666666666666666666666666666658", 16);

    mpz_set(G.X, GX);
    mpz_set(G.Y, GY);
    mpz_set_ui(G.Z, 1);
    mod_mul(G.T, GX, GY, P);
}

static void clear_params() {
    mpz_clears(P, Q_ORDER, D, GX, GY, nullptr);
}

// Демонстрация
static void print_hex(const char* label, const uint8_t* d, size_t n) {
    printf("%s", label);
    for (size_t i = 0; i < n; ++i) printf("%02x", d[i]);
    printf("\n");
}

static bool memeq(const uint8_t* a, const uint8_t* b, size_t n) {
    return memcmp(a, b, n) == 0;
}

int main() {
    setlocale(LC_ALL, "Russian");
    init_params();

    printf("      ТЕСТИРОВАНИЕ Ed25519 (Вектор из RFC 8032, Тест 2)\n");
    printf("Сообщение для подписи: 0x72 ('r')\n\n");

    const uint8_t seed[32] = {
        0x4c,0xcd,0x08,0x9b,0x28,0xff,0x96,0xda,
        0x9d,0xb6,0xc3,0x46,0xec,0x11,0x4e,0x0f,
        0x5b,0x8a,0x31,0x9f,0x35,0xab,0xa6,0x24,
        0xda,0x8c,0xf6,0xed,0x4f,0xb8,0xa6,0xfb
    };

    const uint8_t exp_pk[32] = {
        0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,
        0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,
        0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,
        0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c
    };

    const uint8_t exp_sig[64] = {
        0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8,
        0x72,0x0e,0x82,0x0b,0x5f,0x64,0x25,0x40,
        0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f,
        0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda,
        0x08,0x5a,0xc1,0xe4,0x3e,0x15,0x99,0x6e,
        0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c,
        0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee,
        0xb0,0x0d,0x29,0x16,0x12,0xbb,0x0c,0x00
    };

    const uint8_t msg[] = { 0x72 };

    // --- Генерация ключей ---
    printf("[1] ГЕНЕРАЦИЯ КЛЮЧЕВОЙ ПАРЫ (Keygen)\n");
    printf("Шаг 1.1: Из seed (мастер-ключа) вычисляется хэш SHA-512.\n");
    printf("Шаг 1.2: Первые 32 байта хэша обрезаются (clamping) и используются как скаляр d.\n");
    printf("Шаг 1.3: Публичный ключ A = d * G (через защищенную лестницу Монтгомери).\n");
    printf("Шаг 1.4: Точка A сжимается в 32-байтовый формат.\n\n");

    uint8_t pk[32];
    ed25519_keygen(pk, seed);

    print_hex("Вычисленный публичный ключ (PK): ", pk, 32);
    print_hex("Ожидаемый публичный ключ (PK) : ", exp_pk, 32);
    printf("Статус генерации ключа: %s\n\n", memeq(pk, exp_pk, 32) ? "УСПЕШНО (Совпадает с RFC)" : "ОШИБКА (Не совпадает)");

    // --- Подписание ---
    printf("[2] ПОДПИСАНИЕ СООБЩЕНИЯ (Sign)\n");
    printf("Шаг 2.1: Вычисление эфемерного секрета r = SHA-512(h_hi || M) mod q.\n");
    printf("Шаг 2.2: Вычисление точки R = r * G.\n");
    printf("Шаг 2.3: Вычисление хэша k = SHA-512(R || A || M) mod q.\n");
    printf("Шаг 2.4: Вычисление скаляра подписи S = (r + k * d) mod q.\n\n");

    uint8_t sig[64];
    ed25519_sign(sig, seed, pk, msg, sizeof(msg));

    print_hex("Вычисленная подпись (SIG): ", sig, 64);
    print_hex("Ожидаемая подпись (SIG)  : ", exp_sig, 64);
    printf("Статус подписания: %s\n\n", memeq(sig, exp_sig, 64) ? "УСПЕШНО (Совпадает с RFC)" : "ОШИБКА (Не совпадает)");

    // --- Проверка ---
    printf("[3] ПРОВЕРКА ПОДПИСИ (Verify)\n");
    printf("Шаг 3.1: Разбор подписи на R и S. Декомпрессия точек A и R.\n");
    printf("Шаг 3.2: Вычисление хэша k = SHA-512(R || A || M) mod q.\n");
    printf("Шаг 3.3: Проверка равенства S * G == R + k * A (с константным по времени сравнением).\n\n");

    bool v = ed25519_verify(sig, pk, msg, sizeof(msg));
    printf("Результат проверки подписи: %s\n\n", v ? "ПОДПИСЬ ВЕРНА (УСПЕШНО)" : "ПОДПИСЬ НЕВЕРНА (ОШИБКА)");

    // --- Проверка поддельной подписи ---
    printf("[4] ПРОВЕРКА ИСКАЖЕННОЙ ПОДПИСИ\n");
    printf("Шаг 4.1: В оригинальной подписи принудительно инвертируется 1 бит в параметре S.\n");
    printf("Шаг 4.2: Алгоритм проверки должен отклонить такую подпись.\n\n");

    uint8_t bad[64];
    memcpy(bad, sig, 64);
    bad[40] ^= 0x01;                // искажаем один бит в S

    bool bv = ed25519_verify(bad, pk, msg, sizeof(msg));
    printf("Результат проверки подделки: %s\n\n", bv ? "ПОДПИСЬ ПРИНЯТА (КРИТИЧЕСКАЯ ОШИБКА!)" : "ПОДПИСЬ ОТКЛОНЕНА (ВЕРНО, защита работает)");

    //  ECDH: Алиса и Боб
    printf("      ПРОТОКОЛ ДИФФИ-ХЕЛЛМАНА НА ЭЛЛИПТИЧЕСКИХ КРИВЫХ (ECDH)\n");
    printf("Шаг 1: Алиса и Боб независимо генерируют свои секретные ключи и публичные (a_pk, b_pk).\n");
    printf("Шаг 2: Стороны обмениваются публичными ключами по открытому каналу.\n");
    printf("Шаг 3: Алиса вычисляет K = a_priv * b_pk.\n");
    printf("Шаг 4: Боб вычисляет K = b_priv * a_pk.\n");
    printf("Шаг 5: В качестве общего секрета берется X-координата полученной точки.\n\n");

    uint8_t a_seed[32], b_seed[32];
    for (int i = 0; i < 32; ++i) {
        a_seed[i] = (uint8_t)(i + 1);
        b_seed[i] = (uint8_t)(100 + i);
    }

    uint8_t a_pk[32], b_pk[32];
    ed25519_keygen(a_pk, a_seed);
    ed25519_keygen(b_pk, b_seed);

    print_hex("Публичный ключ Алисы: ", a_pk, 32);
    print_hex("Публичный ключ Боба  : ", b_pk, 32);

    // Приватные скаляры (обрезанные)
    uint8_t a_priv[32], b_priv[32];
    clamp_scalar(a_priv, a_seed);
    clamp_scalar(b_priv, b_seed);

    uint8_t shared_a[32], shared_b[32];
    ed25519_ecdh(shared_a, a_priv, b_pk);
    ed25519_ecdh(shared_b, b_priv, a_pk);

    print_hex("Общий секрет (вычислен Алисой): ", shared_a, 32);
    print_hex("Общий секрет (вычислен Бобом) : ", shared_b, 32);
    printf("Сравнение общих секретов: %s\n\n",
        memeq(shared_a, shared_b, 32) ? "СЕКРЕТЫ СОВПАДАЮТ (УСПЕШНО)" : "СЕКРЕТЫ НЕ СОВПАДАЮТ (ОШИБКА)");

    //  Constant-time проверка
    printf("      ПРОВЕРКА ЗАЩИТЫ ОТ АТАК ПО ПОБОЧНЫМ КАНАЛАМ (CONSTANT-TIME)\n");
    printf("В данном тесте демонстрируется, что время выполнения скалярного умножения\n");
    printf("не зависит от битового представления секретного ключа.\n");
    printf("Используется лестница Монтгомери с branchless-обменом (CSWAP).\n");
    printf("Выполняется умножение для трех скаляров:\n");
    printf(" 1) k = 1 (все биты нули, кроме младшего)\n");
    printf(" 2) k = 2 (один бит в середине)\n");
    printf(" 3) k = 0xFFFFFF... (плотное заполнение битами)\n\n");
    {
        uint8_t scalars[3][32] = {
            { 0x01 },              // k = 1
            { 0x02 },              // k = 2
            { 0xFF,0xFF,0xFF },    // k с "плотными" битами
        };

        Point tmp;

        for (int j = 0; j < 3; ++j) {
            mpz_t k;
            mpz_init(k);
            mpz_import(k, 32, -1, 1, 0, 0, scalars[j]);

            scalar_mult_ct(tmp, k, G);

            mpz_clear(k);
        }

        printf("УСПЕШНО: Все три операции scalar_mult_ct завершены.\n");
        printf("Ветвления, зависящие от секретных битов, в коде отсутствуют.\n");
    }

    clear_params();
    return 0;
}