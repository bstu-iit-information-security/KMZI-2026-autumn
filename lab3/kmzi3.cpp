#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstdint>
#include <cstring>
#include <random>
#include <array>
#include <vector>
#include <algorithm>
#include <stdexcept>

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
                if (c >= '0' && c <= '9')      x += c - '0';
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
        out << std::hex << std::setfill('0');
        for (int i = 3; i >= 0; --i) out << std::setw(16) << v[i];
        return out.str();
    }

    bool isZero() const { return (v[0] | v[1] | v[2] | v[3]) == 0; }
    bool bit(unsigned i) const { return (v[i / 64] >> (i % 64)) & 1ULL; }

    friend bool operator==(const U256& a, const U256& b) {
        return a.v[0] == b.v[0] && a.v[1] == b.v[1] &&
               a.v[2] == b.v[2] && a.v[3] == b.v[3];
    }
    friend bool operator!=(const U256& a, const U256& b) { return !(a == b); }
    friend bool operator<(const U256& a, const U256& b) {
        for (int i = 3; i >= 0; --i)
            if (a.v[i] != b.v[i]) return a.v[i] < b.v[i];
        return false;
    }
    friend bool operator>=(const U256& a, const U256& b) { return !(a < b); }
    friend bool operator>(const U256& a, const U256& b) { return b < a; }
};

static U256 addRaw(const U256& a, const U256& b, uint64_t* carryOut = nullptr) {
    U256 r;
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t s  = a.v[i] + b.v[i];
        uint64_t c1 = (s < a.v[i]) ? 1ULL : 0ULL;
        uint64_t s2 = s + carry;
        uint64_t c2 = (s2 < s) ? 1ULL : 0ULL;
        r.v[i] = s2;
        carry  = c1 | c2;
    }
    if (carryOut) *carryOut = carry;
    return r;
}

static U256 subRaw(const U256& a, const U256& b, uint64_t* borrowOut = nullptr) {
    U256 r;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t t  = a.v[i] - b.v[i];
        uint64_t b1 = (a.v[i] < b.v[i]) ? 1ULL : 0ULL;
        uint64_t t2 = t - borrow;
        uint64_t b2 = (t < borrow) ? 1ULL : 0ULL;
        r.v[i] = t2;
        borrow = b1 | b2;
    }
    if (borrowOut) *borrowOut = borrow;
    return r;
}

static U256 addMod(const U256& a, const U256& b, const U256& m) {
    uint64_t carry = 0;
    U256 s = addRaw(a, b, &carry);

    U256 negM = subRaw(U256(0), m);
    uint64_t cmask = 0ULL - carry;
    U256 toAdd;
    for (int i = 0; i < 4; ++i) toAdd.v[i] = negM.v[i] & cmask;
    U256 t = addRaw(s, toAdd);

    uint64_t borrow = 0;
    U256 diff = subRaw(t, m, &borrow);
    uint64_t mask = 0ULL - (1ULL - borrow);
    U256 res;
    for (int i = 0; i < 4; ++i)
        res.v[i] = (t.v[i] & ~mask) | (diff.v[i] & mask);
    return res;
}

static U256 subMod(const U256& a, const U256& b, const U256& m) {
    uint64_t borrow = 0;
    U256 d = subRaw(a, b, &borrow);
    uint64_t mask = 0ULL - borrow;
    U256 toAdd;
    for (int i = 0; i < 4; ++i) toAdd.v[i] = m.v[i] & mask;
    return addRaw(d, toAdd);
}

static U256 mulMod(const U256& a, const U256& b, const U256& m) {
    U256 r;
    U256 x = a;
    for (int i = 0; i < 256; ++i) {
        uint64_t bit  = b.bit(i);
        uint64_t mask = 0ULL - bit;

        U256 sum = addMod(r, x, m);
        for (int j = 0; j < 4; ++j)
            r.v[j] = (r.v[j] & ~mask) | (sum.v[j] & mask);

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
    U256 exp = subRaw(m, U256(2));
    return powMod(a, exp, m);
}

struct Sha256 {
    struct Digest { uint8_t b[32]{}; };

    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint64_t bits = 0;

    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z)  { return (x & y) ^ (~x & z); }
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t bs0(uint32_t x) { return rotr(x, 2)  ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t bs1(uint32_t x) { return rotr(x, 6)  ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t ss0(uint32_t x) { return rotr(x, 7)  ^ rotr(x, 18) ^ (x >> 3); }
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
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(p[4*i]) << 24) | (uint32_t(p[4*i+1]) << 16)
                 | (uint32_t(p[4*i+2]) << 8) | p[4*i+3];
        for (int i = 16; i < 64; ++i)
            w[i] = ss1(w[i-2]) + w[i-7] + ss0(w[i-15]) + w[i-16];

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = hh + bs1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = bs0(a) + maj(a, b, c);
            hh = g; g = f; f = e; e = d + t1;
            d = c;  c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    Digest digest(const string& s) {
        bits = (uint64_t)s.size() * 8;
        size_t n = s.size();
        size_t total = ((n + 9 + 63) / 64) * 64;
        const size_t MAX_MSG = 4096;
        if (total > MAX_MSG) throw runtime_error("message too long");

        uint8_t m[MAX_MSG]{};
        for (size_t i = 0; i < n; ++i) m[i] = (uint8_t)s[i];
        m[n] = 0x80;
        uint64_t L = bits;
        for (int i = 0; i < 8; ++i) m[total - 1 - i] = (uint8_t)(L >> (8 * i));

        for (size_t i = 0; i < total; i += 64) block(m + i);

        uint8_t out[32]{};
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 4; ++j)
                out[4*i + j] = (uint8_t)(h[i] >> (24 - 8*j));

        Digest result;
        for (int i = 0; i < 32; ++i) result.b[i] = out[i];
        return result;
    }
};

static U256 hashToU256(const string& msg) {
    Sha256 sha;
    auto d = sha.digest(msg);
    U256 r;
    for (int i = 0; i < 4; ++i) {
        uint64_t w = 0;
        for (int j = 0; j < 8; ++j)
            w = (w << 8) | d.b[i*8 + j];
        r.v[3 - i] = w;
    }
    return r;
}

struct Point {
    U256 x, y;
    bool inf;

    Point() : inf(true) {}
    Point(const U256& X, const U256& Y) : x(X), y(Y), inf(false) {}

    static Point infinity() { return Point(); }
};

struct Curve {
    U256 p, a, b, q;
    Point G;

    Point add(const Point& P, const Point& Q) const {
        if (P.inf) return Q;
        if (Q.inf) return P;

        if (P.x == Q.x) {
            if (P.y != Q.y || P.y.isZero()) return Point::infinity();
            return dbl(P);
        }

        U256 num = subMod(Q.y, P.y, p);
        U256 den = subMod(Q.x, P.x, p);
        U256 lam = mulMod(num, modInv(den, p), p);

        U256 x3 = subMod(subMod(mulMod(lam, lam, p), P.x, p), Q.x, p);
        U256 y3 = subMod(mulMod(lam, subMod(P.x, x3, p), p), P.y, p);
        return Point(x3, y3);
    }

    Point dbl(const Point& P) const {
        if (P.inf || P.y.isZero()) return Point::infinity();

        U256 three(3);
        U256 num = addMod(mulMod(three, mulMod(P.x, P.x, p), p), a, p);
        U256 den = addMod(P.y, P.y, p);
        U256 lam = mulMod(num, modInv(den, p), p);

        U256 x3 = subMod(mulMod(lam, lam, p), addMod(P.x, P.x, p), p);
        U256 y3 = subMod(mulMod(lam, subMod(P.x, x3, p), p), P.y, p);
        return Point(x3, y3);
    }

    bool onCurve(const Point& P) const {
        if (P.inf) return true;
        U256 y2  = mulMod(P.y, P.y, p);
        U256 x2  = mulMod(P.x, P.x, p);
        U256 x3  = mulMod(x2, P.x, p);
        U256 rhs = addMod(addMod(x3, mulMod(a, P.x, p), p), b, p);
        return y2 == rhs;
    }
};

static const int WNAF_W = 5;
static const int WNAF_TABLE_SIZE = 1 << (WNAF_W - 2);

static vector<int> wnafDigits(const U256& k, int w) {
    vector<int> digits;
    U256 kk = k;
    int window = 1 << w;
    int half   = window >> 1;

    while (!kk.isZero() && digits.size() < 300) {
        if (!kk.bit(0)) {
            digits.push_back(0);
        } else {
            int d = (int)(kk.v[0] & (uint64_t)(window - 1));
            if (d >= half) d -= window;
            digits.push_back(d);
            if (d > 0) kk = subRaw(kk, U256((uint64_t)d));
            else       kk = addRaw(kk, U256((uint64_t)(-d)));
        }

        U256 next;
        next.v[0] = (kk.v[0] >> 1) | (kk.v[1] << 63);
        next.v[1] = (kk.v[1] >> 1) | (kk.v[2] << 63);
        next.v[2] = (kk.v[2] >> 1) | (kk.v[3] << 63);
        next.v[3] = kk.v[3] >> 1;
        kk = next;
    }
    return digits;
}

struct WnafTable {
    array<Point, WNAF_TABLE_SIZE> pts;
};

static WnafTable buildWnafTable(const Point& P, const Curve& E) {
    WnafTable T;
    Point P2 = E.dbl(P);
    T.pts[0] = P;
    for (int i = 1; i < WNAF_TABLE_SIZE; ++i)
        T.pts[i] = E.add(T.pts[i-1], P2);
    return T;
}

static Point ctLookup(const WnafTable& T, int idx) {
    Point res;
    res.inf = true;
    res.x = U256(0);
    res.y = U256(0);

    for (int i = 0; i < WNAF_TABLE_SIZE; ++i) {
        uint64_t mask = 0ULL - (uint64_t)(i == idx);

        for (int j = 0; j < 4; ++j) {
            res.x.v[j] ^= (res.x.v[j] ^ T.pts[i].x.v[j]) & mask;
            res.y.v[j] ^= (res.y.v[j] ^ T.pts[i].y.v[j]) & mask;
        }
        uint64_t ir = res.inf ? 1ULL : 0ULL;
        uint64_t is = T.pts[i].inf ? 1ULL : 0ULL;
        uint64_t inew = ir ^ ((ir ^ is) & mask);
        res.inf = (inew != 0);
    }
    return res;
}

static Point scalarMulWnaf(const U256& k, const Point& P, const Curve& E) {
    if (k.isZero() || P.inf) return Point::infinity();

    vector<int> digits = wnafDigits(k, WNAF_W);
    WnafTable table = buildWnafTable(P, E);

    Point R;
    for (int i = (int)digits.size() - 1; i >= 0; --i) {
        R = E.dbl(R);
        int d = digits[i];
        if (d != 0) {
            int absd = d < 0 ? -d : d;
            int idx  = (absd - 1) / 2;

            Point T = ctLookup(table, idx);

            uint64_t negMask = 0ULL - (uint64_t)(d < 0);
            U256 negY = subMod(U256(0), T.y, E.p);
            for (int j = 0; j < 4; ++j)
                T.y.v[j] = (T.y.v[j] & ~negMask) | (negY.v[j] & negMask);

            R = E.add(R, T);
        }
    }
    return R;
}

static U256 ctRandomScalar(const U256& q) {
    static random_device rd;
    static mt19937_64 gen(rd());

    const int ITER = 64;
    U256 result(1);
    int found = 0;

    for (int i = 0; i < ITER; ++i) {
        U256 r;
        for (int j = 0; j < 4; ++j) r.v[j] = gen();

        int valid = (!r.isZero() && r < q) ? 1 : 0;
        int take  = valid & (1 - found);
        uint64_t mask = 0ULL - (uint64_t)take;
        for (int j = 0; j < 4; ++j)
            result.v[j] = (result.v[j] & ~mask) | (r.v[j] & mask);
        found |= take;
    }
    return result;
}

struct Signature { U256 r, s; };

static Signature ecdsaSign(const Curve& E, const U256& d, const string& msg) {
    U256 z = hashToU256(msg);
    if (z >= E.q) z = subRaw(z, E.q);

    while (true) {
        U256 k = ctRandomScalar(E.q);
        if (k.isZero()) continue;

        Point C = scalarMulWnaf(k, E.G, E);
        if (C.inf) continue;

        U256 r = C.x;
        if (r >= E.q) r = subRaw(r, E.q);
        if (r.isZero()) continue;

        U256 kinv = modInv(k, E.q);
        U256 s = mulMod(kinv, addMod(z, mulMod(r, d, E.q), E.q), E.q);
        if (s.isZero()) continue;

        return { r, s };
    }
}

static bool ecdsaVerify(const Curve& E, const Point& Q,
                        const string& msg, const Signature& sig) {
    if (sig.r.isZero() || sig.s.isZero()) return false;
    if (sig.r >= E.q || sig.s >= E.q)     return false;

    U256 z = hashToU256(msg);
    if (z >= E.q) z = subRaw(z, E.q);

    U256 w  = modInv(sig.s, E.q);
    U256 u1 = mulMod(z, w, E.q);
    U256 u2 = mulMod(sig.r, w, E.q);

    Point A = scalarMulWnaf(u1, E.G, E);
    Point B = scalarMulWnaf(u2, Q,   E);
    Point C = E.add(A, B);
    if (C.inf) return false;

    U256 v = C.x;
    if (v >= E.q) v = subRaw(v, E.q);
    return v == sig.r;
}

int main() {
    Curve E;

    E.p = U256::fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    E.a = U256(0);
    E.b = U256(7);
    E.q = U256::fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    E.G.x = U256::fromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    E.G.y = U256::fromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    E.G.inf = false;

    cout << "G on curve: " << (E.onCurve(E.G) ? "OK" : "ERROR") << "\n\n";

    U256 dA = ctRandomScalar(E.q);
    U256 dB = ctRandomScalar(E.q);

    Point QA = scalarMulWnaf(dA, E.G, E);
    Point QB = scalarMulWnaf(dB, E.G, E);
    Point SA = scalarMulWnaf(dA, QB,  E);
    Point SB = scalarMulWnaf(dB, QA,  E);

    cout << "ECDH:\n";
    cout << "  QA.x = " << QA.x.hex() << "\n";
    cout << "  QB.x = " << QB.x.hex() << "\n";
    cout << "  SA.x = " << SA.x.hex() << "\n";
    cout << "  SB.x = " << SB.x.hex() << "\n";
    cout << "  shared equal: "
         << ((SA.x == SB.x && SA.y == SB.y) ? "OK" : "ERROR") << "\n\n";

    U256 d = ctRandomScalar(E.q);
    Point Q = scalarMulWnaf(d, E.G, E);

    string msg = "test message";
    Signature sig = ecdsaSign(E, d, msg);

    cout << "ECDSA:\n";
    cout << "  d    = " << d.hex() << "\n";
    cout << "  Q.x  = " << Q.x.hex() << "\n";
    cout << "  r    = " << sig.r.hex() << "\n";
    cout << "  s    = " << sig.s.hex() << "\n";

    cout << "  verify good:    "
         << (ecdsaVerify(E, Q, msg, sig) ? "OK" : "FAIL") << "\n";

    Signature bad = sig;
    bad.s.v[0] ^= 1;
    cout << "  verify bad s:   "
         << (ecdsaVerify(E, Q, msg, bad) ? "OK" : "REJECTED") << "\n";

    cout << "  verify bad msg: "
         << (ecdsaVerify(E, Q, msg + "!", sig) ? "OK" : "REJECTED") << "\n";

    return 0;
}