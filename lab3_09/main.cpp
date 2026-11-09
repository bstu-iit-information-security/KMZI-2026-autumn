#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <cstdint>
#include <cstring>
#include <random>

using namespace std;


//  СТБ 34.101.45, кривая Вейерштрасса, проективные координаты Якоби,
//  скалярное умножение Fixed-Window + Constant-Time LUT.
//  Параметры кривой: secp256k1 (все константы согласованы, ord(G) = q).
//  Формулы ЭЦП: СТБ 34.101.45.



// U256 (256-битное слово) 
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
    bool isOdd()  const { return (v[0] & 1ULL) != 0; }
    bool bit(unsigned i) const { return (v[i / 64] >> (i % 64)) & 1ULL; }

    friend bool operator==(const U256& a, const U256& b) {
        return a.v[0] == b.v[0] && a.v[1] == b.v[1] && a.v[2] == b.v[2] && a.v[3] == b.v[3];
    }
    friend bool operator!=(const U256& a, const U256& b) { return !(a == b); }
    friend bool operator<(const U256& a, const U256& b) {
        for (int i = 3; i >= 0; --i) if (a.v[i] != b.v[i]) return a.v[i] < b.v[i];
        return false;
    }
    friend bool operator>=(const U256& a, const U256& b) { return !(a < b); }
};


// Арифметика U256
static U256 addRaw(const U256& a, const U256& b, uint64_t* carryOut = nullptr) {
    U256 r; uint64_t carry = 0;
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
    U256 r; uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t bi = b.v[i];
        uint64_t t = bi + borrow;
        uint64_t carry = (t < bi) ? 1ULL : 0ULL;
        r.v[i] = a.v[i] - t;
        borrow = (a.v[i] < t) | carry;
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
    // p простое -> a^(p-2) mod p
    return powMod(a, subRaw(m, U256(2)), m);
}


//Constant-time примитивы
// 0xFF..FF если x == y, иначе 0x00..00 — без ветвлений.
static uint64_t ct_mask_eq(uint64_t x, uint64_t y) {
    uint64_t d = x ^ y;
    uint64_t t = ((d | (0ULL - d)) >> 63) ^ 1ULL;   // 1 если d==0, иначе 0
    return 0ULL - t;
}

// mask = 0x00..00 -> a ; mask = 0xFF..FF -> b
static U256 ct_sel(const U256& a, const U256& b, uint64_t mask) {
    U256 r;
    for (int i = 0; i < 4; ++i)
        r.v[i] = (a.v[i] & ~mask) | (b.v[i] & mask);
    return r;
}


// 1. Точка в координатах Якоби + кривая + арифметика ЭК
struct JacobiPoint {
    U256 X, Y, Z;
    bool inf = true;

    JacobiPoint() = default;
    JacobiPoint(U256 x, U256 y, U256 z, bool i = false)
        : X(x), Y(y), Z(z), inf(i) {
    }

    static JacobiPoint infinity() {
        return JacobiPoint(U256(0), U256(1), U256(0), true);
    }
    static JacobiPoint fromAffine(U256 x, U256 y) {
        return JacobiPoint(x, y, U256(1), false);
    }
};

struct Curve {
    U256 p, a, b;
    U256 q;
    U256 gx, gy;
    JacobiPoint G;

    Curve() {
        // secp256k1 — все параметры согласованы, ord(G) = q
        p = U256::fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
        a = U256(0);
        b = U256(7);
        q = U256::fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        gx = U256::fromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
        gy = U256::fromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
        G = JacobiPoint::fromAffine(gx, gy);
    }

    //Jacobi -> affine
    void toAffine(const JacobiPoint& P, U256& x, U256& y, bool& inf) const {
        if (P.inf) { x = U256(0); y = U256(0); inf = true; return; }
        U256 zi = modInv(P.Z, p);
        U256 zi2 = mulMod(zi, zi, p);
        U256 zi3 = mulMod(zi2, zi, p);
        x = mulMod(P.X, zi2, p);
        y = mulMod(P.Y, zi3, p);
        inf = false;
    }

    //Удвоение (Jacobi, формулы)
    JacobiPoint dbl(const JacobiPoint& P) const {
        if (P.inf || P.Y.isZero()) return JacobiPoint::infinity();

        U256 Y2 = mulMod(P.Y, P.Y, p);
        U256 S = mulMod(U256(4), mulMod(P.X, Y2, p), p);
        U256 Z2 = mulMod(P.Z, P.Z, p);
        U256 Z4 = mulMod(Z2, Z2, p);
        U256 M = addMod(mulMod(U256(3), mulMod(P.X, P.X, p), p),
            mulMod(a, Z4, p), p);

        U256 X3 = subMod(mulMod(M, M, p), addMod(S, S, p), p);
        U256 Y4 = mulMod(Y2, Y2, p);
        U256 Y3 = subMod(mulMod(M, subMod(S, X3, p), p),
            mulMod(U256(8), Y4, p), p);
        U256 Z3 = mulMod(U256(2), mulMod(P.Y, P.Z, p), p);
        return JacobiPoint(X3, Y3, Z3, false);
    }

    //Сложение (Jacobi)
    JacobiPoint add(const JacobiPoint& P1, const JacobiPoint& P2) const {
        if (P1.inf) return P2;
        if (P2.inf) return P1;

        U256 Z1_2 = mulMod(P1.Z, P1.Z, p);
        U256 Z2_2 = mulMod(P2.Z, P2.Z, p);
        U256 U1 = mulMod(P1.X, Z2_2, p);
        U256 U2 = mulMod(P2.X, Z1_2, p);

        U256 Z1_3 = mulMod(Z1_2, P1.Z, p);
        U256 Z2_3 = mulMod(Z2_2, P2.Z, p);
        U256 S1 = mulMod(P1.Y, Z2_3, p);
        U256 S2 = mulMod(P2.Y, Z1_3, p);

        U256 H = subMod(U2, U1, p);
        U256 R = subMod(S2, S1, p);

        if (H.isZero()) {
            if (R.isZero()) return dbl(P1);
            return JacobiPoint::infinity();
        }

        U256 H2 = mulMod(H, H, p);
        U256 H3 = mulMod(H2, H, p);
        U256 U1H2 = mulMod(U1, H2, p);

        U256 X3 = subMod(subMod(mulMod(R, R, p), H3, p), addMod(U1H2, U1H2, p), p);
        U256 Y3 = subMod(mulMod(R, subMod(U1H2, X3, p), p), mulMod(S1, H3, p), p);
        U256 Z3 = mulMod(H, mulMod(P1.Z, P2.Z, p), p);
        return JacobiPoint(X3, Y3, Z3, false);
    }

    //  3. Fixed-window скалярное умножение + constant-time LUT
    //  Таблица: [O, P, 2P, ..., (2^w - 1)P]
    //  Все элементы всегда читаются; выбор — через арифметическую маску.
    JacobiPoint scalarMulFixedWindow(const U256& k,
        const JacobiPoint& P,
        unsigned w = 4) const {
        const unsigned table_size = 1u << w;   // 16

        // предвычисление
        JacobiPoint table[16];
        table[0] = JacobiPoint::infinity();
        table[1] = P;
        for (unsigned i = 2; i < table_size; ++i)
            table[i] = add(table[i - 1], P);

        JacobiPoint R = JacobiPoint::infinity();

        // фиксированное число окон по 256 бит
        const int WINDOWS = (256 + (int)w - 1) / (int)w;   // 64 при w=4

        for (int wi = WINDOWS - 1; wi >= 0; --wi) {
            for (unsigned j = 0; j < w; ++j) R = dbl(R);

            // извлекаем окно — без ветвления по значениям битов
            unsigned window = 0;
            unsigned base = (unsigned)wi * w;
            for (unsigned j = 0; j < w; ++j) {
                unsigned bi = base + j;
                unsigned b = (bi < 256) ? (unsigned)k.bit(bi) : 0u;
                window |= b << j;
            }

            // ---- constant-time LUT: линейный проход по всей таблице ----
            JacobiPoint selected = JacobiPoint::infinity();
            for (unsigned i = 0; i < table_size; ++i) {
                uint64_t mask = ct_mask_eq((uint64_t)i, (uint64_t)window);
                selected.X = ct_sel(selected.X, table[i].X, mask);
                selected.Y = ct_sel(selected.Y, table[i].Y, mask);
                selected.Z = ct_sel(selected.Z, table[i].Z, mask);
                uint64_t ia = selected.inf ? 1ULL : 0ULL;
                uint64_t ib = table[i].inf ? 1ULL : 0ULL;
                selected.inf = (((ia & ~mask) | (ib & mask)) != 0);
            }

            R = add(R, selected);
        }
        return R;
    }

    bool onCurve(const JacobiPoint& P) const {
        if (P.inf) return true;
        U256 x, y; bool inf;
        toAffine(P, x, y, inf);
        if (inf) return true;
        U256 y2 = mulMod(y, y, p);
        U256 x2 = mulMod(x, x, p);
        U256 rhs = addMod(addMod(mulMod(x2, x, p), mulMod(a, x, p), p), b, p);
        return y2 == rhs;
    }
};


//SHA-256
struct SHA256 {
    struct Digest { uint8_t b[32]{}; };
    uint32_t h[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };

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
        for (int i = 0; i < 16; ++i)
            w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) | ((uint32_t)p[4 * i + 2] << 8) | p[4 * i + 3];
        for (int i = 16; i < 64; ++i)
            w[i] = ss1(w[i - 2]) + w[i - 7] + ss0(w[i - 15]) + w[i - 16];
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = hh + bs1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = bs0(a) + maj(a, b, c);
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    Digest digest(const string& s) {
        size_t n = s.size();
        size_t total = ((n + 9 + 63) / 64) * 64;
        const size_t MAX_MSG = 4096;
        uint8_t m[MAX_MSG]{};
        for (size_t i = 0; i < n; ++i) m[i] = (uint8_t)s[i];
        m[n] = 0x80;
        uint64_t L = (uint64_t)n * 8;
        for (int i = 0; i < 8; ++i) m[total - 1 - i] = (uint8_t)(L >> (8 * i));
        for (size_t i = 0; i < total; i += 64) block(m + i);
        Digest r;
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 4; ++j)
                r.b[4 * i + j] = (uint8_t)(h[i] >> (24 - 8 * j));
        return r;
    }
};

static U256 hashToU256(const string& msg) {
    SHA256 sha;
    auto d = sha.digest(msg);
    U256 r;
    for (int i = 0; i < 32; ++i)
        r.v[i / 8] = (r.v[i / 8] << 8) | d.b[i];
    return r;
}

// приводим хэш к (0, q)
static U256 hashToScalar(const string& msg, const U256& q) {
    U256 z = hashToU256(msg);
    while (z >= q) z = subRaw(z, q);
    return z;
}


//2. СТБ 34.101.45
//  Подпись:   C = k*G; r = x_C mod q; s = (r*d + k*e) mod q
//  Проверка:  v = e^{-1}; z1 = s*v; z2 = -r*v;
//             C' = z1*G + z2*Q; R = x_C' mod q; R == r ?
struct Signature { U256 r, s; };

static Signature stbSign(const Curve& C, const string& msg,
    const U256& d, const U256& k) {
    U256 e = hashToScalar(msg, C.q);

    JacobiPoint Cpt = C.scalarMulFixedWindow(k, C.G, 4);

    U256 xc, yc; bool inf;
    C.toAffine(Cpt, xc, yc, inf);
    if (inf) return { U256(0), U256(0) };

    U256 r = xc;
    while (r >= C.q) r = subRaw(r, C.q);

    U256 rd = mulMod(r, d, C.q);
    U256 ke = mulMod(k, e, C.q);
    U256 s = addMod(rd, ke, C.q);
    return { r, s };
}

static bool stbVerify(const Curve& C, const string& msg,
    const JacobiPoint& Q, const Signature& sig) {
    if (sig.r.isZero() || sig.s.isZero()) return false;
    if (sig.r >= C.q || sig.s >= C.q)     return false;

    U256 e = hashToScalar(msg, C.q);

    U256 v = modInv(e, C.q);
    U256 z1 = mulMod(sig.s, v, C.q);
    U256 z2 = subMod(U256(0), mulMod(sig.r, v, C.q), C.q);

    JacobiPoint A = C.scalarMulFixedWindow(z1, C.G, 4);
    JacobiPoint B = C.scalarMulFixedWindow(z2, Q, 4);
    JacobiPoint X = C.add(A, B);

    if (X.inf) return false;
    U256 xc, yc; bool inf;
    C.toAffine(X, xc, yc, inf);
    if (inf) return false;

    U256 R = xc;
    while (R >= C.q) R = subRaw(R, C.q);
    return R == sig.r;
}


int main() {
    Curve C;

    cout << "=== STB 34.101.45, Weierstrass, Jacobi, Fixed-Window CT ===\n";
    cout << "Curve: secp256k1\n";
    cout << "Base point G on curve: " << boolalpha << C.onCurve(C.G) << "\n\n";

    //ECDH
    U256 aliceD = U256(0x123456789ULL);
    U256 bobD = U256(0x987654321ULL);

    JacobiPoint aliceQ = C.scalarMulFixedWindow(aliceD, C.G, 4);
    JacobiPoint bobQ = C.scalarMulFixedWindow(bobD, C.G, 4);

    JacobiPoint sharedA = C.scalarMulFixedWindow(aliceD, bobQ, 4);
    JacobiPoint sharedB = C.scalarMulFixedWindow(bobD, aliceQ, 4);

    U256 sAx, sAy, sBx, sBy; bool iA, iB;
    C.toAffine(sharedA, sAx, sAy, iA);
    C.toAffine(sharedB, sBx, sBy, iB);

    cout << "[1] ECDH\n";
    cout << "  Alice shared x = " << sAx.hex() << "\n";
    cout << "  Bob   shared x = " << sBx.hex() << "\n";
    cout << "  Equal: " << boolalpha << (sAx == sBx && sAy == sBy) << "\n\n";

    //STB 34.101.45
    U256 d = U256(0x13579BDFULL);
    JacobiPoint Q = C.scalarMulFixedWindow(d, C.G, 4);

    U256 k = U256(0x1122334455667788ULL);
    string msg = "Information Security Lab 3 - Variant 9";

    Signature sig = stbSign(C, msg, d, k);
    cout << "[2] STB 34.101.45\n";
    cout << "  r = " << sig.r.hex() << "\n";
    cout << "  s = " << sig.s.hex() << "\n";

    bool ok = stbVerify(C, msg, Q, sig);
    bool okChanged = stbVerify(C, "Tampered Message", Q, sig);

    Signature bad = sig;
    bad.s.v[0] ^= 1ULL;
    bool okCorrupt = stbVerify(C, msg, Q, bad);

    cout << "  Verify (original)    : " << boolalpha << ok << "\n";
    cout << "  Verify (changed msg) : " << boolalpha << okChanged << "\n";
    cout << "  Verify (corrupted s) : " << boolalpha << okCorrupt << "\n";

    return 0;
}
