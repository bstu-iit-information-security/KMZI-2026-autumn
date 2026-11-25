#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <random>
#include <algorithm>
#include <boost/multiprecision/cpp_int.hpp>

using boost::multiprecision::cpp_int;
using BigInt = cpp_int;


const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

class SHA256 {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t bufLen;

    static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    void transform(const uint8_t* chunk) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t(chunk[i * 4]) << 24) |
                   (uint32_t(chunk[i * 4 + 1]) << 16) |
                   (uint32_t(chunk[i * 4 + 2]) << 8) |
                   uint32_t(chunk[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + K256[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

public:
    SHA256() {
        h[0] = 0x6a09e667; h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
        h[4] = 0x510e527f; h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
        len = 0;
        bufLen = 0;
    }

    void update(const uint8_t* data, size_t size) {
        len += size;
        while (size > 0) {
            size_t take = 64 - bufLen;
            if (take > size) take = size;
            std::memcpy(buf + bufLen, data, take);
            bufLen += take;
            data += take;
            size -= take;
            if (bufLen == 64) {
                transform(buf);
                bufLen = 0;
            }
        }
    }

    void final(uint8_t hash[32]) {
        uint64_t bitLen = len * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (bufLen != 56) update(&zero, 1);

        uint8_t lenBytes[8];
        for (int i = 0; i < 8; ++i)
            lenBytes[i] = uint8_t((bitLen >> (56 - i * 8)) & 0xFF);

        update(lenBytes, 8);

        for (int i = 0; i < 8; ++i) {
            hash[i * 4]     = uint8_t((h[i] >> 24) & 0xFF);
            hash[i * 4 + 1] = uint8_t((h[i] >> 16) & 0xFF);
            hash[i * 4 + 2] = uint8_t((h[i] >> 8) & 0xFF);
            hash[i * 4 + 3] = uint8_t(h[i] & 0xFF);
        }
    }
};


BigInt fromHex(const std::string& s) {
    BigInt r = 0;
    for (char c : s) {
        int v = -1;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;
        r <<= 4;
        r += v;
    }
    return r;
}

std::string toHex(BigInt x, size_t width = 0) {
    if (x == 0) return std::string(width ? width : 1, '0');
    std::string s;
    while (x > 0) {
        int v = (x & 0xF).convert_to<int>();
        s += "0123456789abcdef"[v];
        x >>= 4;
    }
    std::reverse(s.begin(), s.end());
    while (s.size() < width) s.insert(s.begin(), '0');
    return s;
}

BigInt modFunc(const BigInt& a, const BigInt& m) {
    BigInt r = a % m;
    if (r < 0) r += m;
    return r;
}

BigInt modAdd(const BigInt& a, const BigInt& b, const BigInt& m) {
    return modFunc(a + b, m);
}

BigInt modSub(const BigInt& a, const BigInt& b, const BigInt& m) {
    return modFunc(a - b, m);
}

BigInt modMul(const BigInt& a, const BigInt& b, const BigInt& m) {
    return modFunc(a * b, m);
}

int bitLength(const BigInt& n) {
    if (n == 0) return 0;
    int bits = 0;
    BigInt t = n;
    while (t > 0) {
        t >>= 1;
        ++bits;
    }
    return bits;
}

BigInt modPowFixed(BigInt base, const BigInt& exp, const BigInt& mod, int bits) {
    BigInt result = 1 % mod;
    base = modFunc(base, mod);

    for (int i = bits - 1; i >= 0; --i) {
        result = modMul(result, result, mod);
        if (((exp >> i) & 1) != 0) {
            result = modMul(result, base, mod);
        }
    }
    return result;
}


BigInt modInvFermat(const BigInt& a, const BigInt& prime) {
    return modPowFixed(modFunc(a, prime), prime - 2, prime, bitLength(prime));
}



struct Curve {
    BigInt p, a, b, q;
    BigInt Gx, Gy;
};

struct Point {
    BigInt x, y;
    bool inf;

    Point() : x(0), y(0), inf(true) {}
    Point(const BigInt& X, const BigInt& Y, bool isInf = false)
        : x(X), y(Y), inf(isInf) {}
};

Point pointDouble(const Point& P, const Curve& C) {
    if (P.inf || P.y == 0) return Point();

    const BigInt& p = C.p;

    BigInt x2 = modMul(P.x, P.x, p);
    BigInt num = modAdd(modMul(BigInt(3), x2, p), C.a, p);
    BigInt den = modMul(BigInt(2), P.y, p);

    BigInt inv = modInvFermat(den, p);          
    BigInt s = modMul(num, inv, p);

    BigInt x3 = modSub(modMul(s, s, p), modMul(BigInt(2), P.x, p), p);
    BigInt y3 = modSub(modMul(s, modSub(P.x, x3, p), p), P.y, p);

    return Point(x3, y3, false);
}

Point pointAdd(const Point& P, const Point& Q, const Curve& C) {
    if (P.inf) return Q;
    if (Q.inf) return P;

    const BigInt& p = C.p;

    if (P.x == Q.x) {
        if (modAdd(P.y, Q.y, p) == 0) return Point(); 
        return pointDouble(P, C);                     
    }

    BigInt dx = modSub(Q.x, P.x, p);
    BigInt dy = modSub(Q.y, P.y, p);

    BigInt inv = modInvFermat(dx, p);              
    BigInt s = modMul(dy, inv, p);

    BigInt x3 = modSub(modSub(modMul(s, s, p), P.x, p), Q.x, p);
    BigInt y3 = modSub(modMul(s, modSub(P.x, x3, p), p), P.y, p);

    return Point(x3, y3, false);
}


void cswap(Point& A, Point& B, int bit) {
    BigInt mask = bit ? ((BigInt(1) << 256) - 1) : BigInt(0);

    BigInt dx = (A.x ^ B.x) & mask;
    A.x ^= dx;
    B.x ^= dx;

    BigInt dy = (A.y ^ B.y) & mask;
    A.y ^= dy;
    B.y ^= dy;

    int m = -bit;
    int ai = A.inf ? 1 : 0;
    int bi = B.inf ? 1 : 0;
    int d = (ai ^ bi) & m;

    A.inf = ((ai ^ d) != 0);
    B.inf = ((bi ^ d) != 0);
}


Point scalarMul(const Point& P, const BigInt& k, const Curve& C, int bits = 256) {
    Point R0;          
    Point R1 = P;

    for (int i = bits - 1; i >= 0; --i) {
        int bit = ((k >> i) & 1).convert_to<int>();

        cswap(R0, R1, bit);
        R1 = pointAdd(R0, R1, C);
        R0 = pointDouble(R0, C);
        cswap(R0, R1, bit);
    }

    return R0;
}



BigInt randomBigInt(const BigInt& max) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;

    int bytes = (bitLength(max) + 7) / 8;
    BigInt r = 0;

    for (int i = 0; i < bytes; ++i) {
        r <<= 8;
        r += (dist(gen) & 0xFF);
    }

    return r % max;
}

BigInt hashToInt(const std::string& msg, const BigInt& q) {
    uint8_t digest[32];
    SHA256 sha;
    sha.update(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
    sha.final(digest);

    BigInt h = 0;
    for (int i = 0; i < 32; ++i) {
        h <<= 8;
        h += digest[i];
    }

    return modFunc(h, q);
}



struct Signature {
    BigInt r, s;
};

Signature ecdsaSign(const std::string& msg, const BigInt& d, const Curve& C) {
    BigInt e = hashToInt(msg, C.q);

    while (true) {
        BigInt k = randomBigInt(C.q);
        if (k == 0) continue;

        Point G(C.Gx, C.Gy, false);
        Point Cpt = scalarMul(G, k, C);
        if (Cpt.inf) continue;

        BigInt r = modFunc(Cpt.x, C.q);
        if (r == 0) continue;

        BigInt kInv = modInvFermat(k, C.q); 
        BigInt s = modMul(kInv, modAdd(e, modMul(r, d, C.q), C.q), C.q);

        if (s == 0) continue;

        return {r, s};
    }
}

bool ecdsaVerify(const std::string& msg, const Signature& sig, const Point& Q, const Curve& C) {
    if (sig.r <= 0 || sig.r >= C.q) return false;
    if (sig.s <= 0 || sig.s >= C.q) return false;

    BigInt e = hashToInt(msg, C.q);

    BigInt w = modInvFermat(sig.s, C.q);
    BigInt u1 = modMul(e, w, C.q);
    BigInt u2 = modMul(sig.r, w, C.q);

    Point G(C.Gx, C.Gy, false);
    Point P1 = scalarMul(G, u1, C); 
    Point P2 = scalarMul(Q, u2, C);

    Point Cpt = pointAdd(P1, P2, C);
    if (Cpt.inf) return false;

    BigInt R = modFunc(Cpt.x, C.q);
    return R == sig.r;
}



int main() {
    
    Curve C;
    C.p  = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    C.a  = fromHex("0");
    C.b  = fromHex("7");
    C.q  = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    C.Gx = fromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    C.Gy = fromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

    Point G(C.Gx, C.Gy, false);

    
    BigInt dA = randomBigInt(C.q);
    BigInt dB = randomBigInt(C.q);
    if (dA == 0) dA = 1;
    if (dB == 0) dB = 1;

    Point QA = scalarMul(G, dA, C);
    Point QB = scalarMul(G, dB, C);

    Point SA = scalarMul(QB, dA, C);
    Point SB = scalarMul(QA, dB, C);

    std::cout << "===== ECDH =====\n";
    std::cout << "dA       = " << toHex(dA, 64) << "\n";
    std::cout << "QA.x     = " << toHex(QA.x, 64) << "\n";
    std::cout << "QB.x     = " << toHex(QB.x, 64) << "\n";
    std::cout << "SharedA  = " << toHex(SA.x, 64) << "\n";
    std::cout << "SharedB  = " << toHex(SB.x, 64) << "\n";
    std::cout << "ECDH equal: " << (SA.x == SB.x ? "true" : "false") << "\n\n";

    
    BigInt d = randomBigInt(C.q);
    if (d == 0) d = 1;

    Point Q = scalarMul(G, d, C);

    std::string msg = "test message for ECDSA variant 3";

    Signature sig = ecdsaSign(msg, d, C);
    bool ok = ecdsaVerify(msg, sig, Q, C);

    std::cout << "===== ECDSA =====\n";
    std::cout << "d        = " << toHex(d, 64) << "\n";
    std::cout << "Q.x      = " << toHex(Q.x, 64) << "\n";
    std::cout << "r        = " << toHex(sig.r, 64) << "\n";
    std::cout << "s        = " << toHex(sig.s, 64) << "\n";
    std::cout << "Verify original: " << (ok ? "true" : "false") << "\n";

    
    Signature bad = sig;
    bad.s = modAdd(bad.s, BigInt(1), C.q);

    bool badOk = ecdsaVerify(msg, bad, Q, C);
    std::cout << "Verify tampered s: " << (badOk ? "true" : "false") << "\n";

    return 0;
}
