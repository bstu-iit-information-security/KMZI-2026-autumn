#include "Curves.h"

Curves::Curves(u64 p, u64 a, u64 b, u64 Gx, u64 Gy, u64 q)
    : p_(p), a_(a), b_(b), q_(q), G_(Gx, Gy)
{
    if (p_ == 0)          throw std::invalid_argument("modulus p must be non-zero");
    if (!isNonSingular()) throw std::invalid_argument("singular curve");
    if (!isOnCurve(G_))   throw std::invalid_argument("base point G is not on curve");
}

bool Curves::isOnCurve(const Point& P) const noexcept {
    if (P.infinity) return true;
    u64 left = mulmod(P.y, P.y, p_);
    u64 right = (mulmod(mulmod(P.x, P.x, p_), P.x, p_)
        + mulmod(a_, P.x, p_) + b_) % p_;
    return left == right;
}

Curves::Point Curves::add(const Point& P, const Point& Q) const {
    if (P.infinity) return Q;
    if (Q.infinity) return P;

    u64 lambda;
    if (P.x == Q.x) {
        if ((P.y + Q.y) % p_ == 0) return Point();
        u64 num = (3 * mulmod(P.x, P.x, p_) + a_) % p_;
        u64 den = (2 * P.y) % p_;
        lambda = mulmod(num, modInverse(den, p_), p_);
    }
    else {
        u64 num = (Q.y + p_ - P.y) % p_;
        u64 den = (Q.x + p_ - P.x) % p_;
        lambda = mulmod(num, modInverse(den, p_), p_);
    }

    u64 x3 = (mulmod(lambda, lambda, p_) + 2 * p_ - P.x - Q.x) % p_;
    u64 y3 = (mulmod(lambda, (P.x + p_ - x3) % p_, p_) + p_ - P.y) % p_;
    return Point(x3, y3);
}

Curves::Point Curves::dbl(const Point& P) const {
    return add(P, P);
}

Curves::Point Curves::mul(u64 k, const Point& P) const {
    Point R, Q = P;
    while (k) {
        if (k & 1ULL) R = add(R, Q);
        Q = dbl(Q);
        k >>= 1;
    }
    return R;
}

// Условный обмен через маску: bit ∈ {0,1}
void Curves::cswap(Point& A, Point& B, u64 bit) noexcept {
    u64 mask = static_cast<u64>(-static_cast<long long>(bit));
    u64 ax = A.x, ay = A.y, bx = B.x, by = B.y;
    u64 t;
    t = (ax ^ bx) & mask; A.x ^= t; B.x ^= t;
    t = (ay ^ by) & mask; A.y ^= t; B.y ^= t;
    u64 ai = A.infinity ? 1ULL : 0ULL;
    u64 bi = B.infinity ? 1ULL : 0ULL;
    t = (ai ^ bi) & mask;
    A.infinity = (ai ^ t) != 0;
    B.infinity = (bi ^ t) != 0;
}

void Curves::cselect(Point& dst, const Point& A, const Point& B, u64 bit) noexcept {
    u64 mask = static_cast<u64>(-static_cast<long long>(bit));
    dst.x = (A.x & ~mask) | (B.x & mask);
    dst.y = (A.y & ~mask) | (B.y & mask);
    u64 ai = A.infinity ? 1ULL : 0ULL;
    u64 bi = B.infinity ? 1ULL : 0ULL;
    dst.infinity = ((ai & ~mask) | (bi & mask)) != 0;
}

Curves::u64 Curves::cmov(u64 a, u64 b, u64 bit) noexcept {
    u64 mask = static_cast<u64>(-static_cast<long long>(bit));
    return (a & ~mask) | (b & mask);
}

Curves::Point Curves::mulConstantTime(u64 k, const Point& P) const {
    Point R0;           // infinity
    Point R1 = P;

    for (int i = 63; i >= 0; --i) {
        u64 bit = (k >> i) & 1ULL;

        cswap(R0, R1, bit);

        Point sum = add(R0, R1);   // R0 + R1
        Point dblR1 = dbl(R1);     // 2 * R1

        // R0 ← sum ; R1 ← dblR1  (после cswap обратно)
        cselect(R0, R0, sum, 1); // всегда sum
        cselect(R1, R1, dblR1, 1); // всегда dblR1

        cswap(R0, R1, bit);        // возвращаем
    }
    return R0;
}

bool Curves::constantTimeEqual(const Point& A, const Point& B) const noexcept {
    u64 ai = A.infinity ? 1ULL : 0ULL;
    u64 bi = B.infinity ? 1ULL : 0ULL;
    u64 infDiff = ai ^ bi;
    u64 diff = (A.x ^ B.x) | (A.y ^ B.y) | infDiff;
    return diff == 0;
}

//  Проверка инвариантов 
bool Curves::validateInvariants() const noexcept {
    if (p_ == 0) return false;
    if (!isNonSingular()) return false;
    if (G_.infinity) return false;
    if (!isOnCurve(G_)) return false;

    // q * G == O
    Point qG = mul(q_, G_);
    return qG.infinity;
}

// Модульная арифметика 
Curves::u64 Curves::mulmod(u64 a, u64 b, u64 m) noexcept {
    if (m == 0) return 0;
    u64 result = 0;
    a %= m;
    while (b) {
        if (b & 1ULL)
            result = (result >= m - a) ? (result - (m - a)) : (result + a);
        a = (a >= m - a) ? (a - (m - a)) : (a + a);
        b >>= 1;
    }
    return result;
}

Curves::u64 Curves::modInverse(u64 a, u64 m) {
    long long t = 0, newT = 1;
    long long r = static_cast<long long>(m);
    long long newR = static_cast<long long>(a % m);
    while (newR != 0) {
        long long qt = r / newR;
        long long tmpT = t - qt * newT; t = newT; newT = tmpT;
        long long tmpR = r - qt * newR; r = newR; newR = tmpR;
    }
    if (r != 1) throw std::runtime_error("modInverse: not invertible");
    if (t < 0) t += static_cast<long long>(m);
    return static_cast<u64>(t);
}

Curves::u64 Curves::modInverseConstantTime(u64 a, u64 p) noexcept {
    u64 result = 1;
    u64 base = a % p;
    u64 exp = p - 2; // p простое
    // Фиксированное число итераций = 64
    for (int i = 0; i < 64; ++i) {
        u64 bit = (exp >> i) & 1ULL;
        u64 factor = cmov(1ULL, base, bit);
        result = mulmod(result, factor, p);
        base = mulmod(base, base, p);
    }
    return result;
}

bool Curves::isNonSingular() const noexcept {
    u64 a3 = mulmod(mulmod(a_, a_, p_), a_, p_);
    u64 b2 = mulmod(b_, b_, p_);
    u64 val = (mulmod(4, a3, p_) + mulmod(27, b2, p_)) % p_;
    return val != 0;
}
