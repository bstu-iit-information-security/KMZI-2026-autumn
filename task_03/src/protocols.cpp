#include "protocols.h"
#include "ct_secure.h"
#include <gmp.h>   // только арифметика больших чисел по модулю q

// ================================================================ SHA-512

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static uint64_t rotr(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static void sha512Block(Sha512* s, const uint8_t* block) {
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) v = (v << 8) | block[8 * i + j];
        w[i] = v;
    }
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    uint64_t e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 80; ++i) {
        uint64_t S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = h + S1 + ch + K512[i] + w[i];
        uint64_t S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

void sha512Init(Sha512* s) {
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
    for (int i = 0; i < 8; ++i) s->h[i] = iv[i];
    s->totalLen = 0;
    s->bufLen = 0;
}

void sha512Update(Sha512* s, const uint8_t* data, size_t len) {
    s->totalLen += len;
    for (size_t i = 0; i < len; ++i) {
        s->buf[s->bufLen++] = data[i];
        if (s->bufLen == 128) { sha512Block(s, s->buf); s->bufLen = 0; }
    }
}

void sha512Final(Sha512* s, uint8_t out[64]) {
    uint64_t bitLen = s->totalLen * 8;
    uint8_t pad = 0x80;
    sha512Update(s, &pad, 1);
    uint8_t zero = 0;
    while (s->bufLen != 112) sha512Update(s, &zero, 1);
    for (int i = 0; i < 8; ++i) sha512Update(s, &zero, 1);           // старшие 64 бита длины
    uint8_t lenBytes[8];
    for (int i = 0; i < 8; ++i) lenBytes[i] = (uint8_t)(bitLen >> (56 - 8 * i));
    sha512Update(s, lenBytes, 8);
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 8; ++j) out[8 * i + j] = (uint8_t)(s->h[i] >> (56 - 8 * j));
}

void sha512(const uint8_t* data, size_t len, uint8_t out[64]) {
    Sha512 s;
    sha512Init(&s);
    sha512Update(&s, data, len);
    sha512Final(&s, out);
}

// ================================================================ скаляры (GMP: только mod q)

static void bytesToMpz(mpz_t z, const uint8_t* b, size_t n) { mpz_import(z, n, -1, 1, 0, 0, b); }

static void mpzToBytes32(const mpz_t z, uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = 0;
    size_t count = 0;
    uint8_t tmp[64];
    mpz_export(tmp, &count, -1, 1, 0, 0, z);
    for (size_t i = 0; i < count && i < 32; ++i) out[i] = tmp[i];
}

static void loadQ(mpz_t q) { bytesToMpz(q, curve().q, 32); }

// SHA-512(...) mod q
static void hashToScalar(const uint8_t digest[64], uint8_t out[32]) {
    mpz_t z, q;
    mpz_inits(z, q, NULL);
    bytesToMpz(z, digest, 64);
    loadQ(q);
    mpz_mod(z, z, q);
    mpzToBytes32(z, out);
    mpz_clears(z, q, NULL);
}

static void clampScalar(const uint8_t h[32], uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = h[i];
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
}

// ================================================================ EdDSA

void eddsaKeyFromSeed(const uint8_t seed[32], KeyPair* kp) {
    uint8_t h[64];
    sha512(seed, 32, h);
    for (int i = 0; i < 32; ++i) { kp->seed[i] = seed[i]; kp->prefix[i] = h[32 + i]; }
    clampScalar(h, kp->scalar);
    Point A = SecureMultiply(kp->scalar, pointBase());   // секретный скаляр: только constant-time умножение
    pointEncode(A, kp->publicKey);
}

void eddsaSign(const KeyPair& kp, const uint8_t* msg, size_t msgLen, uint8_t sig[64]) {
    uint8_t digest[64], r[32], k[32];

    Sha512 s;
    sha512Init(&s);
    sha512Update(&s, kp.prefix, 32);
    sha512Update(&s, msg, msgLen);
    sha512Final(&s, digest);
    hashToScalar(digest, r);                              // r = SHA-512(prefix || M) mod q

    Point R = SecureMultiply(r, pointBase());             // R = r * G
    pointEncode(R, sig);

    sha512Init(&s);
    sha512Update(&s, sig, 32);
    sha512Update(&s, kp.publicKey, 32);
    sha512Update(&s, msg, msgLen);
    sha512Final(&s, digest);
    hashToScalar(digest, k);                              // k = SHA-512(R || A || M) mod q

    mpz_t zr, zk, za, zS, q;
    mpz_inits(zr, zk, za, zS, q, NULL);
    bytesToMpz(zr, r, 32);
    bytesToMpz(zk, k, 32);
    bytesToMpz(za, kp.scalar, 32);
    loadQ(q);
    mpz_mul(zS, zk, za);
    mpz_add(zS, zS, zr);
    mpz_mod(zS, zS, q);                                   // S = (r + k * a) mod q
    mpzToBytes32(zS, sig + 32);
    mpz_clears(zr, zk, za, zS, q, NULL);
}

bool eddsaVerify(const uint8_t publicKey[32], const uint8_t* msg, size_t msgLen, const uint8_t sig[64]) {
    Point A, R;
    if (!pointDecode(publicKey, &A)) return false;
    if (!pointDecode(sig, &R)) return false;

    mpz_t zS, q;
    mpz_inits(zS, q, NULL);
    bytesToMpz(zS, sig + 32, 32);
    loadQ(q);
    bool sOk = mpz_cmp(zS, q) < 0;                        // требуем S < q
    mpz_clears(zS, q, NULL);
    if (!sOk) return false;

    uint8_t digest[64], k[32];
    Sha512 s;
    sha512Init(&s);
    sha512Update(&s, sig, 32);
    sha512Update(&s, publicKey, 32);
    sha512Update(&s, msg, msgLen);
    sha512Final(&s, digest);
    hashToScalar(digest, k);

    Point left = pointMulDoubleAndAdd(sig + 32, pointBase());          // S * G
    Point right = pointAdd(R, pointMulDoubleAndAdd(k, A));             // R + k * A
    return pointEqual(left, right) == 1;                               // публичные данные
}

// ================================================================ ECDH

bool ecdhSharedSecret(const uint8_t scalar[32], const uint8_t peerPublic[32], uint8_t shared[32]) {
    Point Q;
    if (!pointDecode(peerPublic, &Q)) return false;
    Point S = SecureMultiply(scalar, Q);
    if (pointEqual(S, pointIdentity()) == 1) return false;            // вырожденная точка малого порядка
    pointEncode(S, shared);
    return true;
}
