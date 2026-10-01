#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <cstdint>
#include <cstring>
#include <random>

using namespace std;


struct U256 {
    uint64_t v[4]{};

    U256() = default;
    U256(uint64_t x) { v[0] = x; }

    static U256 fromHex(const string& s) {
        U256 r;
        string h = s;
        if (h.rfind("0x", 0) == 0 || h.rfind("0X", 0) == 0) h = h.substr(2);
        size_t pos = h.size();
        for (int i = 0; i < 4 && pos > 0; ++i) {
            size_t start = (pos >= 16 ? pos - 16 : 0);
            string part = h.substr(start, pos - start);
            uint64_t x = 0;
            for (char c : part) {
                x <<= 4;
                if (c >= '0' && c <= '9') x += c - '0';
                else if (c >= 'a' && c <= 'f') x += c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') x += c - 'A' + 10;
            }
            r.v[i] = x;
            pos = start;
        }
        return r;
    }

    string hex() const {
        ostringstream out;
        out << std::hex << setfill('0');
        for (int i = 3; i >= 0; --i) out << setw(16) << v[i];
        return out.str();
    }

    bool isZero() const { return (v[0] | v[1] | v[2] | v[3]) == 0; }
    bool isOdd() const { return (v[0] & 1ULL) != 0; }
    bool bit(unsigned i) const { return (v[i / 64] >> (i % 64)) & 1ULL; }

    friend bool operator==(const U256& a, const U256& b) { return a.v[0] == b.v[0] && a.v[1] == b.v[1] && a.v[2] == b.v[2] && a.v[3] == b.v[3]; }
    friend bool operator!=(const U256& a, const U256& b) { return !(a == b); }
    friend bool operator<(const U256& a, const U256& b) {
        for (int i = 3; i >= 0; --i) { if (a.v[i] != b.v[i]) return a.v[i] < b.v[i]; }
        return false;
    }
    friend bool operator>=(const U256& a, const U256& b) { return !(a < b); }
};

static U256 addRaw(const U256& a, const U256& b, uint64_t* carryOut = nullptr) {
    U256 r;
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t s = a.v[i] + b.v[i];
        uint64_t c1 = (s < a.v[i]) ? 1ULL : 0ULL;
        uint64_t s2 = s + carry;
        uint64_t c2 = (s2 < s) ? 1ULL : 0ULL;
        r.v[i] = s2;
        carry = c1 | c2;
    }
    if (carryOut) *carryOut = carry;
    return r;
}

static U256 subRaw(const U256& a, const U256& b, uint64_t* borrowOut = nullptr) {
    U256 r;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t bi = b.v[i];
        uint64_t t = bi + borrow;
        uint64_t carry = (t < bi) ? 1 : 0;
        r.v[i] = a.v[i] - t;
        uint64_t nb = (a.v[i] < t) | carry;
        borrow = nb;
    }
    if (borrowOut) *borrowOut = borrow;
    return r;
}


static U256 addMod(const U256& a, const U256& b, const U256& m) {
    uint64_t carry = 0;
    U256 r = addRaw(a, b, &carry);
    if (carry) {

        U256 delta = subRaw(U256(0), m);
        r = addRaw(r, delta);
        if (r >= m) r = subRaw(r, m);
    }
    else if (r >= m) {
        r = subRaw(r, m);
    }
    return r;
}

static U256 subMod(const U256& a, const U256& b, const U256& m) {
    if (a >= b) return subRaw(a, b);
    U256 t = subRaw(b, a);
    return subRaw(m, t);
}

static U256 shl1(const U256& a) {
    U256 r;
    r.v[0] = a.v[0] << 1;
    r.v[1] = (a.v[1] << 1) | (a.v[0] >> 63);
    r.v[2] = (a.v[2] << 1) | (a.v[1] >> 63);
    r.v[3] = (a.v[3] << 1) | (a.v[2] >> 63);
    return r;
}


static U256 mulMod(const U256& a, const U256& b, const U256& m) {
    U256 x = a;
    U256 r;
    for (int i = 0; i < 256; ++i) {
        if (b.bit(i)) r = addMod(r, x, m);
        x = addMod(x, x, m);
    }
    return r;
}

static U256 powMod(U256 base, U256 exp, const U256& m) {
    U256 r(1);
    for (int i = 0; i < 256; ++i) {
        if (exp.bit(i)) r = mulMod(r, base, m);
        base = mulMod(base, base, m);
    }
    return r;
}

static U256 modInv(const U256& a, const U256& m) {

    return powMod(a, subRaw(m, U256(2)), m);
}

static U256 fromUint64(uint64_t x) { return U256(x); }


struct Curve {
    U256 p = U256::fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43");
    U256 a = U256::fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF40");
    U256 b = U256::fromHex("769C8D8A6A6E5D6B2D1E3A6D4A0E8F4E0A0D2A6F3B1C5D7E9F123456789ABCDE");
    U256 q = U256::fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC95E2EAB40309C4956129C2EF129D6CC");
    U256 gx = U256(0);
    U256 gy = U256::fromHex("65A0E2D4F6A1B7C9D8E7F6A5B4C3D2E1F0123456789ABCDEF0123456789ABCDEF");


    Curve();

    struct Point {
        U256 x{}, y{};
        bool inf = true;
        Point() = default;
        Point(U256 X, U256 Y) :x(X), y(Y), inf(false) {}
        static Point infinity() { return Point(); }
    };

    U256 B, Q, GY;
    Point G;

    static U256 decimal(const string& s) {
        U256 r;
        for (char c : s) {

            U256 x2 = shl1(r);
            U256 x8 = shl1(shl1(shl1(r)));
            r = addRaw(x2, x8);
            r = addRaw(r, U256((uint64_t)(c - '0')));
        }
        return r;
    }

    void normalize() {
        b = B; q = Q; gy = GY; G = Point(U256(0), gy);
    }

    Point add(const Point& P, const Point& Qp) const {
        if (P.inf) return Qp;
        if (Qp.inf) return P;
        if (P.x == Qp.x) {
            if (P.y != Qp.y || P.y.isZero()) return Point::infinity();
            return dbl(P);
        }
        U256 num = subMod(Qp.y, P.y, p);
        U256 den = subMod(Qp.x, P.x, p);
        U256 lam = mulMod(num, modInv(den, p), p);
        U256 x3 = subMod(subMod(mulMod(lam, lam, p), P.x, p), Qp.x, p);
        U256 y3 = subMod(mulMod(lam, subMod(P.x, x3, p), p), P.y, p);
        return Point(x3, y3);
    }

    Point dbl(const Point& P) const {
        if (P.inf || P.y.isZero()) return Point::infinity();
        U256 three = U256(3);
        U256 num = addMod(mulMod(three, mulMod(P.x, P.x, p), p), a, p);
        U256 den = addMod(P.y, P.y, p);
        U256 lam = mulMod(num, modInv(den, p), p);
        U256 x3 = subMod(mulMod(lam, lam, p), addMod(P.x, P.x, p), p);
        U256 y3 = subMod(mulMod(lam, subMod(P.x, x3, p), p), P.y, p);
        return Point(x3, y3);
    }

    Point mulBinary(U256 k, const Point& P) const {
        Point R = Point::infinity();
        Point A = P;
        for (int i = 0; i < 256; ++i) {
            if (k.bit(i)) R = add(R, A);
            A = dbl(A);
        }
        return R;
    }

    static Point selectPoint(const Point& A, const Point& B, unsigned chooseB) {

        uint64_t mask = 0ULL - (uint64_t)chooseB;
        Point R = A;
        auto sel = [](uint64_t x, uint64_t y, uint64_t mask) { return (x & ~mask) | (y & mask); };
        for (int i = 0; i < 4; ++i) {
            R.x.v[i] = sel(A.x.v[i], B.x.v[i], mask);
            R.y.v[i] = sel(A.y.v[i], B.y.v[i], mask);
        }
        uint64_t ia = A.inf ? 1 : 0, ib = B.inf ? 1 : 0;
        R.inf = (sel(ia, ib, mask) != 0);
        return R;
    }


    Point montgomeryLadder(const U256& k, const Point& P) const {
        Point R0 = Point::infinity();
        Point R1 = P;
        for (int i = 255; i >= 0; --i) {
            unsigned bit = k.bit(i);
            Point sum = add(R0, R1);
            Point d0 = dbl(R0);
            Point d1 = dbl(R1);
            R0 = selectPoint(d0, sum, bit);
            R1 = selectPoint(sum, d1, bit);
        }
        return R0;
    }

    struct WNAF {
        int digits[257]{};
        unsigned size = 0;
    };

    WNAF wnaf(U256 k, unsigned width) const {
        WNAF result;
        unsigned window = (1u << width);
        int half = (int)(window >> 1);

        while (!k.isZero() && result.size < 257) {
            int d = 0;
            if (k.isOdd()) {
                unsigned val = 0;
                for (unsigned i = 0; i < width; ++i) {
                    if (k.bit(i)) val |= (1u << i);
                }
                d = (int)val;
                if (d >= half) d -= (int)window;

                if (d > 0) {
                    U256 t = U256((uint64_t)d);
                    k = subRaw(k, t);
                }
                else {
                    U256 t = U256((uint64_t)(-d));
                    k = addRaw(k, t);
                }
            }

            result.digits[result.size++] = d;


            U256 next;
            next.v[3] = k.v[3] >> 1;
            next.v[2] = (k.v[2] >> 1) | (k.v[3] << 63);
            next.v[1] = (k.v[1] >> 1) | (k.v[2] << 63);
            next.v[0] = (k.v[0] >> 1) | (k.v[1] << 63);
            k = next;
        }
        return result;
    }

    Point wnafMul(const U256& k, const Point& P, unsigned width = 5) const {

        const unsigned count = 1u << (width - 2);
        Point table[32];

        table[0] = P;
        Point two = dbl(P);
        for (unsigned i = 1; i < count; ++i) {
            table[i] = add(table[i - 1], two);
        }

        WNAF d = wnaf(k, width);
        Point R = Point::infinity();

        for (int i = (int)d.size - 1; i >= 0; --i) {
            R = dbl(R);
            int di = d.digits[i];

            if (di != 0) {
                unsigned absDi = (unsigned)(di > 0 ? di : -di);
                unsigned idx = (absDi - 1) / 2;

                Point selected = Point::infinity();


                for (unsigned j = 0; j < count; ++j) {
                    unsigned eq = (j == idx);
                    selected = selectPoint(selected, table[j], eq);
                }

                if (di > 0) {
                    R = add(R, selected);
                }
                else {
                    Point neg = selected;
                    if (!neg.inf) {
                        neg.y = subMod(U256(0), neg.y, p);
                    }
                    R = add(R, neg);
                }
            }
        }
        return R;
    }

    bool onCurve(const Point& P) const {
        if (P.inf) return true;
        U256 y2 = mulMod(P.y, P.y, p);
        U256 x2 = mulMod(P.x, P.x, p);
        U256 rhs = addMod(addMod(mulMod(x2, P.x, p), mulMod(a, P.x, p), p), b, p);
        return y2 == rhs;
    }
};

Curve::Curve() {

    B = decimal("54189945433829174764701416670523239872420438478408031144987871676190519198705");
    GY = decimal("48835626907528736105417095645674365354469331933013114027389791773001019124371");
    Q = decimal("115792089237316195423570985008687907853269984665564084120958684413\n");

    U256 two256;
    two256.v[0] = two256.v[1] = two256.v[2] = two256.v[3] = ~0ULL;

    U256 c = decimal("51359303463308904523350978545619999225");
    U256 zero;
    U256 neg = subRaw(zero, c);
    Q = neg;
    normalize();
}
struct SHA256 {
    struct Digest { uint8_t b[32]{}; };
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    uint64_t bits = 0;

    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t bs0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t bs1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t ss0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t ss1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    void block(const uint8_t* p) {
        static const uint32_t K[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) w[i] = (uint32_t(p[4 * i]) << 24) | (uint32_t(p[4 * i + 1]) << 16) | (uint32_t(p[4 * i + 2]) << 8) | p[4 * i + 3];
        for (int i = 16; i < 64; ++i) w[i] = ss1(w[i - 2]) + w[i - 7] + ss0(w[i - 15]) + w[i - 16];
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = hh + bs1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = bs0(a) + maj(a, b, c);
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    Digest digest(const string& s) {
        bits = (uint64_t)s.size() * 8;
        size_t n = s.size();
        size_t total = ((n + 9 + 63) / 64) * 64;

        const size_t MAX_MSG = 4096;
        if (total > MAX_MSG) throw runtime_error("Message is too long for this demo");
        uint8_t m[MAX_MSG]{};
        for (size_t i = 0; i < n; ++i)m[i] = (uint8_t)s[i];
        m[n] = 0x80;
        uint64_t L = bits;
        for (int i = 0; i < 8; ++i)m[total - 1 - i] = (uint8_t)(L >> (8 * i));
        for (size_t i = 0; i < total; i += 64)block(m + i);
        uint8_t out[32]{};
        for (int i = 0; i < 8; ++i) for (int j = 0; j < 4; ++j) out[4 * i + j] = (uint8_t)(h[i] >> (24 - 8 * j));
        Digest result;
        for (int i = 0; i < 32; ++i) result.b[i] = out[i];
        return result;
    }
};

static U256 hashToU256(const string& msg) {
    SHA256 sha;
    auto d = sha.digest(msg);
    U256 r;
    for (int i = 0; i < 32; ++i) {
        r.v[i / 8] = (r.v[i / 8] << 8) | d.b[i];
    }
    return r;
}

static U256 rngScalar(const U256& q) {
    random_device rd;
    mt19937_64 gen(rd());
    U256 r;
    for (int i = 0; i < 4; ++i) r.v[i] = gen();

    while (r.isZero() || r >= q) {
        r.v[0] ^= gen();
        r.v[1] ^= gen();
        r.v[2] ^= gen();
        r.v[3] ^= gen();
    }
    return r;
}

struct Signature { U256 r, s; };

static Signature ecdsaSign(const Curve& C, const string& msg, const U256& d, const U256& k) {
    U256 z = hashToU256(msg);
    if (z >= C.q) z = subRaw(z, C.q);
    Curve::Point R = C.mulBinary(k, C.G);
    U256 r = R.x;
    if (r >= C.q) r = subRaw(r, C.q);
    U256 kinv = modInv(k, C.q);
    U256 rd = mulMod(r, d, C.q);
    U256 s = mulMod(kinv, addMod(z, rd, C.q), C.q);
    return { r,s };
}

static bool ecdsaVerify(const Curve& C, const string& msg, const Curve::Point& Q, const Signature& sig) {
    if (sig.r.isZero() || sig.s.isZero() || sig.r >= C.q || sig.s >= C.q)return false;
    U256 z = hashToU256(msg);
    if (z >= C.q) z = subRaw(z, C.q);
    U256 w = modInv(sig.s, C.q);
    U256 u1 = mulMod(z, w, C.q);
    U256 u2 = mulMod(sig.r, w, C.q);
    Curve::Point A = C.mulBinary(u1, C.G);
    Curve::Point B = C.mulBinary(u2, Q);
    Curve::Point X = C.add(A, B);
    if (X.inf)return false;
    U256 v = X.x;
    if (v >= C.q) v = subRaw(v, C.q);
    return v == sig.r;
}

static bool samePoint(const Curve::Point& A, const Curve::Point& B) {
    if (A.inf || B.inf)return A.inf == B.inf;
    return A.x == B.x && A.y == B.y;
}

static void printPoint(const string& name, const Curve::Point& P) {
    cout << name << " = (\n  x=" << (P.inf ? "INF" : P.x.hex()) << "\n  y=" << (P.inf ? "INF" : P.y.hex()) << "\n)\n";
}

int main() {
    Curve C;
    cout << "STB 34.101.45, Weierstrass, affine, Montgomery Ladder\n";
    cout << "G on curve: " << boolalpha << C.onCurve(C.G) << "\n";

    U256 aliceD = U256(0x123456789ULL);
    U256 bobD = U256(0x987654321ULL);
    Curve::Point aliceQ = C.montgomeryLadder(aliceD, C.G);
    Curve::Point bobQ = C.montgomeryLadder(bobD, C.G);
    Curve::Point sharedA = C.montgomeryLadder(aliceD, bobQ);
    Curve::Point sharedB = C.montgomeryLadder(bobD, aliceQ);
    cout << "ECDH shared secret equal: " << samePoint(sharedA, sharedB) << "\n";


    cout << "\n\nECDSA, Weierstrass, affine, WNAF + constant-time table scan\n";
    U256 d = U256(0x13579BDFULL);
    Curve::Point Q = C.mulBinary(d, C.G);
    U256 scalar = U256(0x2468ACE1ULL);
    Curve::Point normal = C.mulBinary(scalar, C.G);
    Curve::Point wnaf = C.wnafMul(scalar, C.G, 5);
    cout << "WNAF == ordinary multiplication: " << samePoint(normal, wnaf) << "\n";

    U256 k = U256(0x1122334455667788ULL);
    string msg = "Hello ECC";
    Signature sig = ecdsaSign(C, msg, d, k);
    cout << "ECDSA verify: " << ecdsaVerify(C, msg, Q, sig) << "\n";
    cout << "Changed message verify: " << ecdsaVerify(C, "Hello ECC!", Q, sig) << "\n";
    return 0;
}
