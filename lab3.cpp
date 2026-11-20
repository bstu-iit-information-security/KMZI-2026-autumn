#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

using namespace std;

class Big {
public:

    static const int LIMBS = 40;

    uint32_t v[LIMBS];
    int n;
    int s;

    Big() { clear(); }

    explicit Big(unsigned long long x) {
        clear();
        set(x);
    }

    void clear() {
        for (int i = 0; i < LIMBS; i++)
            v[i] = 0;
        n = 0;
        s = 1;
    }

    void set(unsigned long long x) {
        clear();
        if (x != 0) {
            v[0] = (uint32_t)x;
            v[1] = (uint32_t)(x >> 32);
            n = (v[1] != 0) ? 2 : 1;
        }
    }

    void trim() {
        while (n > 0 && v[n - 1] == 0)
            n--;
        if (n == 0)
            s = 1;

        for (int i = n; i < LIMBS; i++)
            v[i] = 0;
    }

    int bitlen() const {
        if (n == 0)
            return 0;
        uint32_t top = v[n - 1];
        int lz = 0;
        for (int i = 31; i >= 0; i--) {
            if ((top >> i) & 1u)
                break;
            lz++;
        }
        return (n - 1) * 32 + (32 - lz);
    }

    int bit(int i) const {
        if (i < 0)
            return 0;
        int limb = i / 32;
        int off = i % 32;
        if (limb >= n)
            return 0;
        return (int)((v[limb] >> off) & 1u);
    }

    int bitFixed(int i) const {
        if (i < 0)
            return 0;
        int limb = i / 32;
        int off = i % 32;
        if (limb >= LIMBS)
            return 0;
        return (int)((v[limb] >> off) & 1u);
    }

    void setBit(int i) {
        if (i < 0)
            return;
        int limb = i / 32;
        int off = i % 32;
        if (limb >= LIMBS)
            return;
        v[limb] |= (uint32_t)1u << off;
        if (n <= limb)
            n = limb + 1;
    }

    int cmpAbs(const Big& o) const {
        if (n != o.n)
            return (n > o.n) ? 1 : -1;
        for (int i = n - 1; i >= 0; i--) {
            if (v[i] != o.v[i])
                return (v[i] > o.v[i]) ? 1 : -1;
        }
        return 0;
    }

    int cmp(const Big& o) const {
        if (n == 0 && o.n == 0)
            return 0;
        if (s != o.s)
            return s;
        return s * cmpAbs(o);
    }

    int cmp(unsigned long long x) const {
        Big t(x);
        return cmp(t);
    }

    void addAbs(const Big& o) {
        uint64_t carry = 0;
        int m = (n > o.n) ? n : o.n;
        for (int i = 0; i < m; i++) {
            uint64_t a = (i < n) ? v[i] : 0;
            uint64_t b = (i < o.n) ? o.v[i] : 0;
            uint64_t cur = a + b + carry;
            v[i] = (uint32_t)cur;
            carry = cur >> 32;
        }
        n = m;
        if (carry != 0 && n < LIMBS)
            v[n++] = (uint32_t)carry;
        trim();
    }

    void subAbs(const Big& o) {
        uint64_t borrow = 0;
        for (int i = 0; i < n; i++) {
            uint64_t a = v[i];
            uint64_t b = ((i < o.n) ? (uint64_t)o.v[i] : 0) + borrow;
            uint64_t d = a - b;
            v[i] = (uint32_t)d;
            borrow = (d >> 63) & 1u;
        }
        trim();
    }

    void add(const Big& o) {
        if (s == o.s) {
            addAbs(o);
        } else if (cmpAbs(o) >= 0) {
            subAbs(o);
        } else {
            Big tmp = o;
            tmp.subAbs(*this);
            *this = tmp;
        }
        trim();
    }

    void sub(const Big& o) {
        Big t = o;
        if (t.n != 0)
            t.s = -t.s;
        add(t);
    }

    void mul(const Big& o) {
        uint32_t t[LIMBS];
        for (int i = 0; i < LIMBS; i++)
            t[i] = 0;

        int sign = s * o.s;
        for (int i = 0; i < n; i++) {
            uint64_t carry = 0;
            for (int j = 0; j < o.n && i + j < LIMBS; j++) {
                uint64_t cur = (uint64_t)t[i + j]
                             + (uint64_t)v[i] * (uint64_t)o.v[j]
                             + carry;
                t[i + j] = (uint32_t)cur;
                carry = cur >> 32;
            }
            int k = i + o.n;
            while (carry != 0 && k < LIMBS) {
                uint64_t cur = (uint64_t)t[k] + carry;
                t[k] = (uint32_t)cur;
                carry = cur >> 32;
                k++;
            }
        }

        for (int i = 0; i < LIMBS; i++)
            v[i] = t[i];
        n = n + o.n;
        if (n > LIMBS)
            n = LIMBS;
        s = sign;
        trim();
    }

    void shlBits(int k) {
        if (n == 0 || k <= 0)
            return;

        int limbs = k / 32;
        int bits = k % 32;
        if (limbs >= LIMBS) {
            clear();
            return;
        }

        if (limbs != 0) {
            if (n + limbs > LIMBS)
                n = LIMBS - limbs;
            for (int i = n - 1; i >= 0; i--)
                v[i + limbs] = v[i];
            for (int i = 0; i < limbs; i++)
                v[i] = 0;
            n += limbs;
        }

        if (bits != 0) {
            uint32_t carry = 0;
            for (int i = 0; i < n; i++) {
                uint32_t cur = v[i];
                v[i] = (cur << bits) | carry;
                carry = cur >> (32 - bits);
            }
            if (carry != 0 && n < LIMBS)
                v[n++] = carry;
        }
        trim();
    }

    void shrBits(int k) {
        if (n == 0 || k <= 0)
            return;

        int limbs = k / 32;
        int bits = k % 32;
        if (limbs >= n) {
            clear();
            return;
        }

        for (int i = 0; i < n - limbs; i++)
            v[i] = v[i + limbs];
        for (int i = n - limbs; i < n; i++)
            v[i] = 0;
        n -= limbs;

        if (bits != 0) {
            uint32_t carry = 0;
            for (int i = n - 1; i >= 0; i--) {
                uint32_t cur = v[i];
                v[i] = (cur >> bits) | carry;
                carry = cur << (32 - bits);
            }
        }
        trim();
    }

    void divmod(Big& q, Big& r, const Big& d) const {
        q.clear();
        r.clear();
        if (n == 0 || d.n == 0)
            return;

        int bits = bitlen();
        for (int i = bits - 1; i >= 0; i--) {
            r.shlBits(1);
            if (bit(i)) {
                if (r.n == 0)
                    r.n = 1;
                r.v[0] |= 1u;
            }
            r.trim();
            if (r.cmpAbs(d) >= 0) {
                r.subAbs(d);
                q.setBit(i);
            }
        }

        q.s = (q.n == 0) ? 1 : s * d.s;
        r.s = (r.n == 0) ? 1 : s;
        q.trim();
        r.trim();
    }

    void mod(const Big& m) {
        Big q, r;
        divmod(q, r, m);
        if (r.s < 0 && r.n != 0) {
            r.s = 1;
            Big t = m;
            t.s = 1;
            t.sub(r);
            r = t;
        }
        r.s = 1;
        *this = r;
    }

    void cmov(const Big& o, uint32_t mask) {
        uint32_t nmask = ~mask;
        for (int i = 0; i < LIMBS; i++)
            v[i] = (v[i] & nmask) | (o.v[i] & mask);
        n = (int)(((uint32_t)n & nmask) | ((uint32_t)o.n & mask));
        s = (int)(((uint32_t)s & nmask) | ((uint32_t)o.s & mask));
    }

    void cswap(Big& o, unsigned int b) {
        uint32_t mask = 0u - (uint32_t)(b & 1u);
        for (int i = 0; i < LIMBS; i++) {
            uint32_t t = mask & (v[i] ^ o.v[i]);
            v[i] ^= t;
            o.v[i] ^= t;
        }
        uint32_t tn = mask & ((uint32_t)n ^ (uint32_t)o.n);
        n = (int)((uint32_t)n ^ tn);
        o.n = (int)((uint32_t)o.n ^ tn);
        uint32_t ts = mask & ((uint32_t)s ^ (uint32_t)o.s);
        s = (int)((uint32_t)s ^ ts);
        o.s = (int)((uint32_t)o.s ^ ts);
    }

    unsigned int ctIsZero() const {
        uint32_t acc = 0;
        for (int i = 0; i < LIMBS; i++)
            acc |= v[i];
        return 1u ^ ((acc | (0u - acc)) >> 31);
    }

    unsigned int ctLess(const Big& o) const {
        uint32_t borrow = 0;
        for (int i = 0; i < LIMBS; i++) {
            uint64_t a = (uint64_t)v[i];
            uint64_t b = (uint64_t)o.v[i] + (uint64_t)borrow;
            uint64_t d = a - b;
            borrow = (uint32_t)((d >> 63) & 1u);
        }
        return borrow;
    }

    unsigned int ctEqual(const Big& o) const {
        uint32_t acc = 0;
        for (int i = 0; i < LIMBS; i++)
            acc |= (v[i] ^ o.v[i]);
        return 1u ^ ((acc | (0u - acc)) >> 31);
    }

    void load(const unsigned char* p, int len) {
        clear();
        if (len <= 0)
            return;
        n = (len + 3) / 4;
        if (n > LIMBS)
            n = LIMBS;
        for (int i = 0; i < len; i++) {
            int pos = len - 1 - i;
            int limb = pos / 4;
            int sh = (pos % 4) * 8;
            if (limb < LIMBS)
                v[limb] |= ((uint32_t)p[i]) << sh;
        }
        trim();
    }

    void store(unsigned char* p, int len) const {
        memset(p, 0, len);
        for (int i = 0; i < len; i++) {
            int pos = len - 1 - i;
            int limb = pos / 4;
            int sh = (pos % 4) * 8;
            if (limb < n)
                p[i] = (unsigned char)(v[limb] >> sh);
        }
    }
};

class Numbers {
public:
    void egcd(Big& g, Big& x, Big& y, const Big& a, const Big& b) const {
        Big old_r = a, r = b;
        Big old_s((unsigned long long)1), ss((unsigned long long)0);
        Big old_t((unsigned long long)0), tt((unsigned long long)1);
        old_r.s = 1;
        r.s = 1;

        while (r.n != 0) {
            Big q, rem;
            old_r.divmod(q, rem, r);

            Big tmp = old_r;
            old_r = r;
            r = rem;

            Big qs = q;
            qs.mul(ss);
            tmp = old_s;
            old_s = ss;
            ss = tmp;
            ss.sub(qs);

            Big qt = q;
            qt.mul(tt);
            tmp = old_t;
            old_t = tt;
            tt = tmp;
            tt.sub(qt);
        }

        g = old_r;
        x = old_s;
        y = old_t;
    }

    int modInv(Big& out, const Big& a, const Big& m) const {
        Big g, x, y;
        egcd(g, x, y, a, m);
        if (g.cmp((unsigned long long)1) != 0)
            return 0;
        out = x;
        out.mod(m);
        return 1;
    }
};

static int hexValue(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

static void fromHex(Big& x, const char* s) {
    unsigned char buf[128];
    int slen = (int)strlen(s);
    if (slen <= 0 || slen > 256) {
        x.clear();
        return;
    }

    int n = 0;
    int i = 0;
    if (slen & 1) {
        int v = hexValue(s[0]);
        if (v < 0) {
            x.clear();
            return;
        }
        buf[n++] = (unsigned char)v;
        i = 1;
    }
    for (; i + 1 < slen; i += 2) {
        int hi = hexValue(s[i]);
        int lo = hexValue(s[i + 1]);
        if (hi < 0 || lo < 0) {
            x.clear();
            return;
        }
        buf[n++] = (unsigned char)((hi << 4) | lo);
    }
    x.load(buf, n);
}

static string toHex(const Big& x, int nbytes) {
    unsigned char buf[128];
    if (nbytes > (int)sizeof(buf))
        nbytes = (int)sizeof(buf);
    x.store(buf, nbytes);

    string s;
    s.resize(nbytes * 2);
    const char* hexd = "0123456789ABCDEF";
    for (int i = 0; i < nbytes; i++) {
        s[2 * i] = hexd[buf[i] >> 4];
        s[2 * i + 1] = hexd[buf[i] & 0xF];
    }
    return s;
}

static int hexToBytes(const char* s, unsigned char* out, int maxlen) {
    int slen = (int)strlen(s);
    if (slen <= 0 || (slen & 1))
        return -1;
    int n = slen / 2;
    if (n > maxlen)
        return -1;
    for (int i = 0; i < n; i++) {
        int hi = hexValue(s[2 * i]);
        int lo = hexValue(s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return n;
}

class SHA256 {
    static uint32_t rotr(uint32_t x, unsigned n) {
        return (x >> n) | (x << (32u - n));
    }

    static uint32_t loadw(const unsigned char* p) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }

    static void storew(unsigned char* p, uint32_t x) {
        p[0] = (unsigned char)(x >> 24);
        p[1] = (unsigned char)(x >> 16);
        p[2] = (unsigned char)(x >> 8);
        p[3] = (unsigned char)x;
    }

    static void block(uint32_t h[8], const unsigned char b[64]) {
        static const uint32_t K[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
        };

        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = loadw(b + 4 * i);
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & bb) ^ (a & c) ^ (bb & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = bb; bb = a; a = t1 + t2;
        }

        h[0] += a; h[1] += bb; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

public:
    static void hash(const unsigned char* data, int len, unsigned char out[32]) {
        uint32_t h[8] = {
            0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
            0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
        };

        const unsigned char* p = data;
        int left = len;
        while (left >= 64) {
            block(h, p);
            p += 64;
            left -= 64;
        }

        unsigned char buf[64];
        memset(buf, 0, 64);
        if (left != 0 && p != 0)
            memcpy(buf, p, left);
        buf[left] = 0x80;

        uint64_t bits = (uint64_t)len * 8u;
        if (left >= 56) {
            block(h, buf);
            memset(buf, 0, 64);
        }
        for (int i = 0; i < 8; i++)
            buf[63 - i] = (unsigned char)(bits >> (8 * i));
        block(h, buf);

        for (int i = 0; i < 8; i++)
            storew(out + 4 * i, h[i]);
    }
};

struct Point {
    Big X, Y, Z;

    void cmov(const Point& o, uint32_t mask) {
        X.cmov(o.X, mask);
        Y.cmov(o.Y, mask);
        Z.cmov(o.Z, mask);
    }
};

class Elliptic {
public:
    Big p, a, b, q, gx, gy;
    Numbers math;

    Elliptic() {

        fromHex(p,  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97");
        fromHex(a,  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94");
        fromHex(b,  "00000000000000000000000000000000000000000000000000000000000000A6");
        fromHex(q,  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893");
        fromHex(gx, "0000000000000000000000000000000000000000000000000000000000000001");
        fromHex(gy, "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14");
    }

    Big addf(const Big& x, const Big& y) const {
        Big r = x;
        r.add(y);
        r.mod(p);
        return r;
    }

    Big subf(const Big& x, const Big& y) const {
        Big r = x;
        r.sub(y);
        r.mod(p);
        return r;
    }

    Big mulf(const Big& x, const Big& y) const {
        Big r = x;
        r.mul(y);
        r.mod(p);
        return r;
    }

    Point inf() const {
        Point O;
        O.X.set(1);
        O.Y.set(1);
        O.Z.clear();
        return O;
    }

    Point G() const {
        Point P;
        P.X = gx;
        P.Y = gy;
        P.Z.set(1);
        return P;
    }

    bool isInf(const Point& P) const {
        return P.Z.ctIsZero() != 0;
    }

    Point dbl(const Point& P) const {
        Big Y2 = mulf(P.Y, P.Y);
        Big S  = mulf(Big((unsigned long long)4), mulf(P.X, Y2));
        Big X2 = mulf(P.X, P.X);
        Big Z2 = mulf(P.Z, P.Z);
        Big Z4 = mulf(Z2, Z2);
        Big M  = addf(mulf(Big((unsigned long long)3), X2), mulf(a, Z4));

        Point R;
        R.X = subf(mulf(M, M), mulf(Big((unsigned long long)2), S));
        Big Y4 = mulf(Y2, Y2);
        R.Y = subf(mulf(M, subf(S, R.X)), mulf(Big((unsigned long long)8), Y4));
        R.Z = mulf(Big((unsigned long long)2), mulf(P.Y, P.Z));
        return R;
    }

    Point add(const Point& P, const Point& Q) const {
        Big Z1sq = mulf(P.Z, P.Z);
        Big Z2sq = mulf(Q.Z, Q.Z);
        Big U1 = mulf(P.X, Z2sq);
        Big U2 = mulf(Q.X, Z1sq);
        Big S1 = mulf(P.Y, mulf(Z2sq, Q.Z));
        Big S2 = mulf(Q.Y, mulf(Z1sq, P.Z));
        Big H  = subf(U2, U1);
        Big R  = subf(S2, S1);

        Big H2 = mulf(H, H);
        Big H3 = mulf(H2, H);

        Point T;
        T.X = subf(subf(mulf(R, R), H3), mulf(Big((unsigned long long)2), mulf(U1, H2)));
        T.Y = subf(mulf(R, subf(mulf(U1, H2), T.X)), mulf(S1, H3));
        T.Z = mulf(H, mulf(P.Z, Q.Z));

        Point D = dbl(P);

        uint32_t hZero = H.ctIsZero();
        uint32_t rZero = R.ctIsZero();

        T.cmov(D, 0u - (hZero & rZero));

        T.cmov(Q, 0u - P.Z.ctIsZero());
        T.cmov(P, 0u - Q.Z.ctIsZero());
        return T;
    }

    Point toAffine(const Point& P) const {
        Big zi;
        if (!math.modInv(zi, P.Z, p))
            zi.clear();

        Big zi2 = mulf(zi, zi);
        Big zi3 = mulf(zi2, zi);

        Point A;
        A.X = mulf(P.X, zi2);
        A.Y = mulf(P.Y, zi3);
        A.Z.set(1);

        A.cmov(inf(), 0u - P.Z.ctIsZero());
        return A;
    }

    bool onCurve(const Point& P) const {
        if (isInf(P))
            return true;
        Point A = toAffine(P);
        Big yy = mulf(A.Y, A.Y);
        Big xx = mulf(A.X, A.X);
        Big rhs = addf(addf(mulf(A.X, xx), mulf(a, A.X)), b);
        return yy.ctEqual(rhs) != 0;
    }

    int modInvP(Big& out, const Big& x) const {
        return math.modInv(out, x, p);
    }

    int modInvQ(Big& out, const Big& x) const {
        return math.modInv(out, x, q);
    }
};

static bool randomBytes(unsigned char* buf, int len) {
#ifdef _WIN32
    typedef BOOLEAN (WINAPI *RtlGenRandomFn)(PVOID, ULONG);
    static RtlGenRandomFn fn = 0;
    if (fn == 0) {
        HMODULE h = LoadLibraryA("advapi32.dll");
        if (h != 0)
            fn = (RtlGenRandomFn)(void*)GetProcAddress(h, "SystemFunction036");
    }
    if (fn != 0)
        return fn((PVOID)buf, (ULONG)len) != 0;
    return false;
#else
    FILE* f = fopen("/dev/urandom", "rb");
    if (f == 0)
        return false;
    size_t got = fread(buf, 1, (size_t)len, f);
    fclose(f);
    return got == (size_t)len;
#endif
}

class FixedWindow {
public:
    static const int WINDOW = 4;
    static const int TABLE_SIZE = 1 << WINDOW;

    Elliptic& E;

    FixedWindow(Elliptic& curve) : E(curve) {}

    static unsigned int ctEqIndex(unsigned int a, unsigned int b) {
        uint32_t x = (uint32_t)(a ^ b);
        return 1u ^ ((x | (0u - x)) >> 31);
    }

    Point ctLookup(const Point table[TABLE_SIZE], unsigned int index) const {
        Point result = E.inf();
        for (unsigned int i = 0; i < (unsigned int)TABLE_SIZE; i++) {
            uint32_t mask = 0u - ctEqIndex(i, index);
            result.X.cmov(table[i].X, mask);
            result.Y.cmov(table[i].Y, mask);
            result.Z.cmov(table[i].Z, mask);
        }
        return result;
    }

    Point multiply(const Big& k, const Point& P) const {
        Point table[TABLE_SIZE];
        table[0] = E.inf();
        table[1] = P;
        for (int i = 2; i < TABLE_SIZE; i++)
            table[i] = E.add(table[i - 1], P);

        Point R = E.inf();
        int totalBits = E.q.bitlen();
        int windows = (totalBits + WINDOW - 1) / WINDOW;

        for (int w = windows - 1; w >= 0; w--) {
            for (int j = 0; j < WINDOW; j++)
                R = E.dbl(R);

            unsigned int index = 0;
            for (int j = 0; j < WINDOW; j++)
                index |= (unsigned int)k.bitFixed(w * WINDOW + j) << j;

            Point T = ctLookup(table, index);
            R = E.add(R, T);
        }
        return R;
    }

    Big randomScalar() const {
        Big k;
        unsigned int found = 0;

        for (int iter = 0; iter < 100; iter++) {
            unsigned char buf[32];
            if (!randomBytes(buf, 32)) {
                fprintf(stderr, "RNG failure\n");
                exit(1);
            }

            Big cand;
            cand.load(buf, 32);

            unsigned int nonZero = 1u ^ cand.ctIsZero();
            unsigned int inRange = cand.ctLess(E.q);
            unsigned int valid = nonZero & inRange;
            unsigned int take = valid & (found ^ 1u);

            k.cmov(cand, 0u - (uint32_t)take);
            found |= valid;
        }

        Big one((unsigned long long)1);
        k.cmov(one, 0u - k.ctIsZero());
        return k;
    }
};

struct KeyPair {
    Big d;
    Point Q;
};

struct Signature {
    Big r;
    Big s;
};

class Stb3410 {
public:
    Elliptic& E;
    FixedWindow& ct;

    Stb3410(Elliptic& curve, FixedWindow& secure) : E(curve), ct(secure) {}

    Big hashMsg(const unsigned char* m, int len) const {
        unsigned char h[32];
        SHA256::hash(m, len, h);
        Big e;
        e.load(h, 32);
        e.mod(E.q);
        if (e.ctIsZero())
            e.set(1);
        return e;
    }

    KeyPair keygen() const {
        KeyPair kp;
        kp.d = ct.randomScalar();
        kp.Q = E.toAffine(ct.multiply(kp.d, E.G()));
        return kp;
    }

    bool ecdh(const Big& d, const Point& Qpeer, Point& shared) const {
        if (!E.onCurve(Qpeer))
            return false;
        shared = E.toAffine(ct.multiply(d, Qpeer));
        return !E.isInf(shared);
    }

    Signature sign(const Big& d, const unsigned char* m, int len) const {
        Big e = hashMsg(m, len);
        Signature sig;

        for (;;) {
            Big k = ct.randomScalar();
            Point C = E.toAffine(ct.multiply(k, E.G()));

            sig.r = C.X;
            sig.r.mod(E.q);
            if (sig.r.ctIsZero())
                continue;

            sig.s = sig.r;
            sig.s.mul(d);

            Big ke = k;
            ke.mul(e);
            sig.s.add(ke);
            sig.s.mod(E.q);

            if (sig.s.ctIsZero())
                continue;
            break;
        }
        return sig;
    }

    bool verify(const Point& Q, const unsigned char* m, int len,
                const Signature& sig) const {
        if (sig.r.ctIsZero() || sig.r.cmp(E.q) >= 0)
            return false;
        if (sig.s.ctIsZero() || sig.s.cmp(E.q) >= 0)
            return false;
        if (!E.onCurve(Q))
            return false;

        Big e = hashMsg(m, len);

        Big v;
        if (!E.modInvQ(v, e))
            return false;

        Big z1 = sig.s;
        z1.mul(v);
        z1.mod(E.q);

        Big z2 = sig.r;
        z2.s = -1;
        z2.mul(v);
        z2.mod(E.q);

        Point C = E.add(ct.multiply(z1, E.G()), ct.multiply(z2, Q));
        if (E.isInf(C))
            return false;

        Point affineC = E.toAffine(C);
        Big R = affineC.X;
        R.mod(E.q);
        return R.ctEqual(sig.r) != 0;
    }
};

int main(int argc, char** argv) {

    const char* defaultMsgHex = "6175207265766F69722C206D6F6E20616D6F757221";
    const char* msgHex = (argc > 1) ? argv[1] : defaultMsgHex;

    unsigned char msg[4096];
    int msgLen = hexToBytes(msgHex, msg, (int)sizeof(msg));
    if (msgLen < 0) {
        fprintf(stderr, "Message must be a raw hex string of even length\n");
        return 1;
    }

    Elliptic E;
    FixedWindow ct(E);
    Stb3410 stb(E, ct);

    KeyPair A = stb.keygen();
    KeyPair B = stb.keygen();

    cout << "dA = " << toHex(A.d, 32) << "\n";
    cout << "QAx = " << toHex(A.Q.X, 32) << "\n";
    cout << "QAy = " << toHex(A.Q.Y, 32) << "\n";
    cout << "dB = " << toHex(B.d, 32) << "\n";
    cout << "QBx = " << toHex(B.Q.X, 32) << "\n";
    cout << "QBy = " << toHex(B.Q.Y, 32) << "\n";

    Point KA, KB;
    bool okA = stb.ecdh(A.d, B.Q, KA);
    bool okB = stb.ecdh(B.d, A.Q, KB);

    cout << "shared_A_x = " << toHex(KA.X, 32) << "\n";
    cout << "shared_B_x = " << toHex(KB.X, 32) << "\n";
    cout << "ecdh_equal = "
         << ((okA && okB && KA.X.ctEqual(KB.X)) ? 1 : 0) << "\n";

    Signature sig = stb.sign(A.d, msg, msgLen);
    cout << "r = " << toHex(sig.r, 32) << "\n";
    cout << "s = " << toHex(sig.s, 32) << "\n";
    cout << "verify = " << (stb.verify(A.Q, msg, msgLen, sig) ? 1 : 0) << "\n";

    Signature bad = sig;
    bad.s.v[0] ^= 0x01u;
    bad.s.trim();

    cout << "s_tampered = " << toHex(bad.s, 32) << "\n";
    cout << "verify_tampered = "
         << (stb.verify(A.Q, msg, msgLen, bad) ? 1 : 0) << "\n";

    return 0;
}
