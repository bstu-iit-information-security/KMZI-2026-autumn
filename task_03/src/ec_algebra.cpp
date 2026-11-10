#include "ec_algebra.h"

typedef unsigned __int128 u128;

static const uint64_t P_LIMBS[4] = {0xffffffffffffffedULL, 0xffffffffffffffffULL,
                                    0xffffffffffffffffULL, 0x7fffffffffffffffULL};
// p - 2, (p - 5) / 8, (p - 1) / 4
static const uint64_t EXP_P_MINUS_2[4]  = {0xffffffffffffffebULL, 0xffffffffffffffffULL,
                                           0xffffffffffffffffULL, 0x7fffffffffffffffULL};
static const uint64_t EXP_P_MINUS_5_D8[4] = {0xfffffffffffffffdULL, 0xffffffffffffffffULL,
                                             0xffffffffffffffffULL, 0x0fffffffffffffffULL};
static const uint64_t EXP_P_MINUS_1_D4[4] = {0xfffffffffffffffbULL, 0xffffffffffffffffULL,
                                             0xffffffffffffffffULL, 0x1fffffffffffffffULL};

// ---------------------------------------------------------------- поле

Fe feZero() { Fe r = {{0, 0, 0, 0}}; return r; }
Fe feOne()  { Fe r = {{1, 0, 0, 0}}; return r; }
Fe feFromU64(uint64_t x) { Fe r = {{x, 0, 0, 0}}; return r; }

Fe feSelect(uint64_t bit, const Fe& a, const Fe& b) {
    uint64_t mask = 0 - (bit & 1);
    Fe r;
    for (int i = 0; i < 4; ++i) r.v[i] = (a.v[i] & mask) | (b.v[i] & ~mask);
    return r;
}

// r = a - P; если был заём (a < P), возвращается a. Без ветвлений.
static Fe condSubP(const Fe& a) {
    Fe t;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        u128 d = (u128)a.v[i] - P_LIMBS[i] - borrow;
        t.v[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 64) & 1;
    }
    return feSelect(borrow, a, t);
}

Fe feAdd(const Fe& a, const Fe& b) {
    Fe s;
    uint64_t c = 0;
    for (int i = 0; i < 4; ++i) {
        u128 t = (u128)a.v[i] + b.v[i] + c;
        s.v[i] = (uint64_t)t;
        c = (uint64_t)(t >> 64);
    }
    return condSubP(s);
}

Fe feSub(const Fe& a, const Fe& b) {
    Fe t;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        u128 d = (u128)a.v[i] - b.v[i] - borrow;
        t.v[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 64) & 1;
    }
    Fe u;
    uint64_t c = 0;
    for (int i = 0; i < 4; ++i) {
        u128 s = (u128)t.v[i] + P_LIMBS[i] + c;
        u.v[i] = (uint64_t)s;
        c = (uint64_t)(s >> 64);
    }
    return feSelect(borrow, u, t);
}

Fe feNeg(const Fe& a) { return feSub(feZero(), a); }

Fe feMul(const Fe& a, const Fe& b) {
    uint64_t r[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            u128 t = (u128)a.v[i] * b.v[j] + r[i + j] + carry;
            r[i + j] = (uint64_t)t;
            carry = (uint64_t)(t >> 64);
        }
        r[i + 4] = carry;
    }
    // 2^256 = 38 (mod p): w = L + 38 * H
    uint64_t w[5];
    uint64_t c = 0;
    for (int i = 0; i < 4; ++i) {
        u128 t = (u128)r[i + 4] * 38 + r[i] + c;
        w[i] = (uint64_t)t;
        c = (uint64_t)(t >> 64);
    }
    w[4] = c;
    // 2^255 = 19 (mod p): отделяем биты выше 254
    uint64_t top = (w[3] >> 63) | (w[4] << 1);
    w[3] &= 0x7fffffffffffffffULL;
    Fe res;
    c = top * 19;
    for (int i = 0; i < 4; ++i) {
        u128 t = (u128)w[i] + c;
        res.v[i] = (uint64_t)t;
        c = (uint64_t)(t >> 64);
    }
    res = condSubP(res);
    return condSubP(res);
}

Fe feSquare(const Fe& a) { return feMul(a, a); }

uint64_t feEqual(const Fe& a, const Fe& b) {
    uint64_t acc = 0;
    for (int i = 0; i < 4; ++i) acc |= a.v[i] ^ b.v[i];
    // acc == 0  ->  1, иначе 0, без ветвления
    return ((acc | (0 - acc)) >> 63) ^ 1;
}

Fe fePow(const Fe& a, const uint64_t e[4]) {
    Fe result = feOne();
    for (int i = 255; i >= 0; --i) {
        result = feSquare(result);
        Fe t = feMul(result, a);
        result = feSelect((e[i / 64] >> (i % 64)) & 1, t, result);
    }
    return result;
}

Fe feInvert(const Fe& a) { return fePow(a, EXP_P_MINUS_2); }

uint64_t feIsNegative(const Fe& a) { return a.v[0] & 1; }

void feToBytes(const Fe& a, uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = (uint8_t)(a.v[i / 8] >> (8 * (i % 8)));
}

bool feFromBytes(const uint8_t in[32], Fe* out) {
    Fe r;
    for (int i = 0; i < 4; ++i) {
        uint64_t w = 0;
        for (int j = 7; j >= 0; --j) w = (w << 8) | in[8 * i + j];
        r.v[i] = w;
    }
    // значение должно быть < p (публичные данные, ветвление допустимо)
    Fe reduced = condSubP(r);
    bool canonical = true;
    for (int i = 0; i < 4; ++i) if (reduced.v[i] != r.v[i]) canonical = false;
    if (r.v[3] >> 63) canonical = false;
    *out = r;
    return canonical;
}

static int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool feFromHex(const char* hex, Fe* out) {
    uint8_t le[32];
    for (int i = 0; i < 32; ++i) {
        int hi = hexVal(hex[2 * i]), lo = hexVal(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        le[31 - i] = (uint8_t)(hi * 16 + lo);
    }
    return feFromBytes(le, out);
}

// ---------------------------------------------------------------- параметры

static CurveParams g_curve;
static bool g_curveReady = false;

static void hexToBytesLE(const char* hex, uint8_t out[32]) {
    for (int i = 0; i < 32; ++i)
        out[31 - i] = (uint8_t)(hexVal(hex[2 * i]) * 16 + hexVal(hex[2 * i + 1]));
}

const CurveParams& curve() {
    if (!g_curveReady) {
        feFromHex("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", &g_curve.d);
        feFromHex("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", &g_curve.Gx);
        feFromHex("6666666666666666666666666666666666666666666666666666666666666658", &g_curve.Gy);
        hexToBytesLE("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", g_curve.q);
        g_curveReady = true;
    }
    return g_curve;
}

// ---------------------------------------------------------------- точки

Point pointIdentity() { Point r; r.X = feZero(); r.Y = feOne(); r.Z = feOne(); return r; }

Point pointFromAffine(const Fe& x, const Fe& y) { Point r; r.X = x; r.Y = y; r.Z = feOne(); return r; }

Point pointBase() { return pointFromAffine(curve().Gx, curve().Gy); }

Point pointNeg(const Point& P) { Point r = P; r.X = feNeg(P.X); return r; }

// A = Z1 Z2, B = A^2, C = X1 X2, D = Y1 Y2, E = d C D, F = B - E, G = B + E
// X3 = A F ((X1+Y1)(X2+Y2) - C - D), Y3 = A G (D - a C) = A G (D + C) при a = -1, Z3 = F G
Point pointAdd(const Point& P, const Point& Q) {
    const Fe& d = curve().d;
    Fe A = feMul(P.Z, Q.Z);
    Fe B = feSquare(A);
    Fe C = feMul(P.X, Q.X);
    Fe D = feMul(P.Y, Q.Y);
    Fe E = feMul(d, feMul(C, D));
    Fe F = feSub(B, E);
    Fe G = feAdd(B, E);
    Fe H = feSub(feSub(feMul(feAdd(P.X, P.Y), feAdd(Q.X, Q.Y)), C), D);
    Point R;
    R.X = feMul(feMul(A, F), H);
    R.Y = feMul(feMul(A, G), feAdd(D, C));
    R.Z = feMul(F, G);
    return R;
}

Point pointDouble(const Point& P) { return pointAdd(P, P); }

void pointToAffine(const Point& P, Fe* x, Fe* y) {
    Fe zi = feInvert(P.Z);
    *x = feMul(P.X, zi);
    *y = feMul(P.Y, zi);
}

uint64_t pointEqual(const Point& P, const Point& Q) {
    uint64_t ex = feEqual(feMul(P.X, Q.Z), feMul(Q.X, P.Z));
    uint64_t ey = feEqual(feMul(P.Y, Q.Z), feMul(Q.Y, P.Z));
    return ex & ey;
}

// -X^2 Z^2 + Y^2 Z^2 = Z^4 + d X^2 Y^2
bool pointOnCurve(const Point& P) {
    Fe X2 = feSquare(P.X), Y2 = feSquare(P.Y), Z2 = feSquare(P.Z);
    Fe lhs = feMul(feSub(Y2, X2), Z2);
    Fe rhs = feAdd(feSquare(Z2), feMul(curve().d, feMul(X2, Y2)));
    return feEqual(lhs, rhs) == 1;
}

void pointEncode(const Point& P, uint8_t out[32]) {
    Fe x, y;
    pointToAffine(P, &x, &y);
    feToBytes(y, out);
    out[31] |= (uint8_t)(feIsNegative(x) << 7);
}

bool pointDecode(const uint8_t in[32], Point* P) {
    uint8_t tmp[32];
    for (int i = 0; i < 32; ++i) tmp[i] = in[i];
    uint64_t sign = tmp[31] >> 7;
    tmp[31] &= 0x7f;
    Fe y;
    if (!feFromBytes(tmp, &y)) return false;
    Fe y2 = feSquare(y);
    Fe u = feSub(y2, feOne());                         // y^2 - 1
    Fe v = feAdd(feMul(curve().d, y2), feOne());       // d y^2 + 1
    Fe v3 = feMul(feSquare(v), v);
    Fe v7 = feMul(feSquare(v3), v);
    Fe x = feMul(feMul(u, v3), fePow(feMul(u, v7), EXP_P_MINUS_5_D8));
    Fe vx2 = feMul(v, feSquare(x));
    if (feEqual(vx2, u) != 1) {
        if (feEqual(vx2, feNeg(u)) != 1) return false; // не квадрат - точки нет
        x = feMul(x, fePow(feFromU64(2), EXP_P_MINUS_1_D4)); // умножаем на sqrt(-1)
    }
    uint64_t xIsZero = feEqual(x, feZero());
    if (xIsZero && sign) return false;
    if (feIsNegative(x) != sign) x = feNeg(x);
    *P = pointFromAffine(x, y);
    return true;
}

Point pointMulDoubleAndAdd(const uint8_t scalar[32], const Point& P) {
    Point R = pointIdentity();
    for (int i = 255; i >= 0; --i) {
        R = pointDouble(R);
        if ((scalar[i / 8] >> (i % 8)) & 1) R = pointAdd(R, P);   // ветвление по биту: небезопасно для секретов
    }
    return R;
}
