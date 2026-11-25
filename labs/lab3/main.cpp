#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
using namespace std;

class Big{
public:
    unsigned long long v[68];
    int n;
    int s;

    Big(){
        clear();
    }

    Big(unsigned long x){
        clear();
        set(x);
    }

    void clear(){
        n = 0;
        s = 1;
        for(int i = 0; i < 68; i++)
            v[i] = 0;
    }

    void trim(){
        while(n > 0 && v[n - 1] == 0)
            n--;
        if(n == 0)
            s = 1;
    }

    void set(unsigned long x){
        clear();
        if(x != 0){
            v[0] = x;
            n = 1;
        }
    }

    int bitlen() const {
        if(n == 0)
            return 0;
        unsigned long long top = v[n - 1];
        int lz = 0;
        for(int i = 63; i >= 0; i--){
            if((top >> i) & 1ull)
                break;
            lz++;
        }
        return (n - 1) * 64 + (64 - lz);
    }

    int bit(int i) const {
        int limb = i / 64;
        int off = i % 64;
        if(limb < 0 || limb >= n)
            return 0;
        return (int)((v[limb] >> off) & 1ull);
    }

    void setBit(int i){
        int limb = i / 64;
        int off = i % 64;
        if(limb < 0 || limb >= 68)
            return;
        v[limb] |= 1ull << off;
        if(n <= limb)
            n = limb + 1;
    }

    int even() const {
        if(n == 0)
            return 1;
        return (v[0] & 1ull) == 0;
    }

    unsigned long long low() const {
        if(n == 0)
            return 0;
        return v[0];
    }

    int cmpAbs(const Big& o) const {
        if(n != o.n)
            return n > o.n ? 1 : -1;
        for(int i = n - 1; i >= 0; i--){
            if(v[i] != o.v[i])
                return v[i] > o.v[i] ? 1 : -1;
        }
        return 0;
    }

    int cmp(const Big& o) const {
        if(n == 0 && o.n == 0)
            return 0;
        if(s != o.s)
            return s;
        return s * cmpAbs(o);
    }

    int cmp(unsigned long x) const {
        Big t(x);
        return cmp(t);
    }

    void addAbs(const Big& o){
        unsigned long long carry = 0;
        int m = n > o.n ? n : o.n;
        for(int i = 0; i < m; i++){
            unsigned long long a = (i < n) ? v[i] : 0;
            unsigned long long b = (i < o.n) ? o.v[i] : 0;
            unsigned long long s1 = a + b;
            unsigned long long c1 = (s1 < a) ? 1ull : 0;
            unsigned long long s2 = s1 + carry;
            unsigned long long c2 = (s2 < s1) ? 1ull : 0;
            v[i] = s2;
            carry = c1 | c2;
        }
        n = m;
        if(carry && n < 68){
            v[n] = carry;
            n++;
        }
    }

    void subAbs(const Big& o){
        unsigned long long borrow = 0;
        for(int i = 0; i < n; i++){
            unsigned long long a = v[i];
            unsigned long long b = (i < o.n) ? o.v[i] : 0;
            unsigned long long s1 = a - b;
            unsigned long long c1 = (s1 > a) ? 1ull : 0;
            unsigned long long s2 = s1 - borrow;
            unsigned long long c2 = (s2 > s1) ? 1ull : 0;
            v[i] = s2;
            borrow = c1 | c2;
        }
        trim();
    }

    void add(const Big& o){
        if(s == o.s){
            addAbs(o);
        }else if(cmpAbs(o) >= 0){
            subAbs(o);
        }else{
            Big tmp = o;
            tmp.subAbs(*this);
            *this = tmp;
        }
        trim();
    }

    void sub(const Big& o){
        Big t = o;
        if(t.n)
            t.s = -t.s;
        add(t);
    }

    void mul(const Big& o){
        unsigned long long t[68];
        for(int i = 0; i < 68; i++)
            t[i] = 0;
        int ns = s * o.s;
        for(int i = 0; i < n; i++){
            unsigned __int128 carry = 0;
            for(int j = 0; j < o.n; j++){
                if(i + j >= 68)
                    break;
                unsigned __int128 cur = (unsigned __int128)t[i + j]
                    + (unsigned __int128)v[i] * o.v[j]
                    + carry;
                t[i + j] = (unsigned long long)cur;
                carry = cur >> 64;
            }
            int k = i + o.n;
            while(carry && k < 68){
                unsigned __int128 cur = (unsigned __int128)t[k] + carry;
                t[k] = (unsigned long long)cur;
                carry = cur >> 64;
                k++;
            }
        }
        for(int i = 0; i < 68; i++)
            v[i] = t[i];
        n = n + o.n;
        if(n > 68)
            n = 68;
        s = ns;
        trim();
    }

    void shlBits(int k){
        if(n == 0 || k <= 0)
            return;
        int limbs = k / 64;
        int bits = k % 64;
        if(limbs){
            if(n + limbs > 68)
                n = 68 - limbs;
            if(n < 0)
                n = 0;
            for(int i = n - 1; i >= 0; i--){
                if(i + limbs < 68)
                    v[i + limbs] = v[i];
            }
            for(int i = 0; i < limbs && i < 68; i++)
                v[i] = 0;
            n += limbs;
            if(n > 68)
                n = 68;
        }
        if(bits){
            unsigned long long carry = 0;
            for(int i = 0; i < n; i++){
                unsigned long long cur = v[i];
                v[i] = (cur << bits) | carry;
                carry = cur >> (64 - bits);
            }
            if(carry && n < 68){
                v[n] = carry;
                n++;
            }
        }
        trim();
    }

    void shrBits(int k){
        if(n == 0 || k <= 0)
            return;
        int limbs = k / 64;
        int bits = k % 64;
        if(limbs >= n){
            clear();
            return;
        }
        for(int i = 0; i < n - limbs; i++)
            v[i] = v[i + limbs];
        for(int i = n - limbs; i < n; i++)
            v[i] = 0;
        n -= limbs;
        if(bits){
            unsigned long long carry = 0;
            for(int i = n - 1; i >= 0; i--){
                unsigned long long cur = v[i];
                v[i] = (cur >> bits) | carry;
                carry = cur << (64 - bits);
            }
        }
        trim();
    }

    unsigned long long divLimb(unsigned long long d){
        unsigned __int128 rem = 0;
        for(int i = n - 1; i >= 0; i--){
            rem = (rem << 64) | v[i];
            v[i] = (unsigned long long)(rem / d);
            rem = rem % d;
        }
        trim();
        return (unsigned long long)rem;
    }

    void divmod(Big& q, Big& r, const Big& d) const {
        q.clear();
        r.clear();
        if(n == 0 || d.n == 0)
            return;
        int bits = bitlen();
        for(int i = bits - 1; i >= 0; i--){
            r.shlBits(1);
            if(bit(i)){
                if(r.n == 0)
                    r.n = 1;
                r.v[0] |= 1ull;
            }
            r.trim();
            if(r.cmpAbs(d) >= 0){
                r.subAbs(d);
                q.setBit(i);
            }
        }
        q.s = (q.n == 0) ? 1 : s * d.s;
        r.s = (r.n == 0) ? 1 : s;
        q.trim();
        r.trim();
    }

    void mod(const Big& m){
        Big q, r;
        divmod(q, r, m);
        if(r.s < 0 && r.n != 0){
            r.s = 1;
            Big t = m;
            t.s = 1;
            t.sub(r);
            r = t;
        }
        r.s = 1;
        *this = r;
    }

    void cswap(Big& o, unsigned int b){
        unsigned long long mask = 0ull - (unsigned long long)(b & 1u);
        for(int i = 0; i < 68; i++){
            unsigned long long t = mask & (v[i] ^ o.v[i]);
            v[i] ^= t;
            o.v[i] ^= t;
        }
        unsigned int im = (unsigned int)mask;
        unsigned int tn = im & ((unsigned int)n ^ (unsigned int)o.n);
        n ^= (int)tn;
        o.n ^= (int)tn;
        unsigned int ts = im & ((unsigned int)s ^ (unsigned int)o.s);
        s ^= (int)ts;
        o.s ^= (int)ts;
    }

    void load(const unsigned char* p, int len){
        clear();
        if(len <= 0)
            return;
        n = (len + 7) / 8;
        if(n > 68)
            n = 68;
        for(int i = 0; i < len; i++){
            int pos = len - 1 - i;
            int limb = pos / 8;
            int sh = (pos % 8) * 8;
            if(limb < 68)
                v[limb] |= ((unsigned long long)p[i]) << sh;
        }
        trim();
    }

    void store(unsigned char* p, int len) const {
        memset(p, 0, len);
        for(int i = 0; i < len; i++){
            int pos = len - 1 - i;
            int limb = pos / 8;
            int sh = (pos % 8) * 8;
            if(limb < n)
                p[i] = (unsigned char)(v[limb] >> sh);
        }
    }
};

class Numbers{
public:
    void gcd(Big& g, const Big& a, const Big& b){
        Big x = a;
        Big y = b;
        x.s = 1;
        y.s = 1;
        while(y.n != 0){
            Big q, r;
            x.divmod(q, r, y);
            x = y;
            y = r;
        }
        g = x;
    }

    void egcd(Big& g, Big& x, Big& y, const Big& a, const Big& b){
        Big old_r = a, r = b;
        Big old_s(1), ss(0);
        Big old_t(0), tt(1);
        old_r.s = 1;
        r.s = 1;
        while(r.n != 0){
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

    int modInv(Big& out, const Big& a, const Big& m){
        Big g, x, y;
        egcd(g, x, y, a, m);
        if(g.cmp(1ul) != 0)
            return 0;
        out = x;
        out.mod(m);
        return 1;
    }
};

static void fromhex(Big& x, const char* s){
    unsigned char buf[128];
    int slen = (int)strlen(s);
    int n = 0;
    int i = 0;
    if(slen & 1){
        unsigned v = 0;
        char c = s[0];
        if(c >= '0' && c <= '9') v = c - '0';
        else if(c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else if(c >= 'a' && c <= 'f') v = c - 'a' + 10;
        buf[n++] = (unsigned char)v;
        i = 1;
    }
    for(; i + 1 < slen; i += 2){
        unsigned hi = 0, lo = 0;
        char a = s[i], b = s[i + 1];
        if(a >= '0' && a <= '9') hi = a - '0';
        else if(a >= 'A' && a <= 'F') hi = a - 'A' + 10;
        else if(a >= 'a' && a <= 'f') hi = a - 'a' + 10;
        if(b >= '0' && b <= '9') lo = b - '0';
        else if(b >= 'A' && b <= 'F') lo = b - 'A' + 10;
        else if(b >= 'a' && b <= 'f') lo = b - 'a' + 10;
        buf[n++] = (unsigned char)((hi << 4) | lo);
    }
    x.load(buf, n);
}

static string tohex(const Big& x, int nbytes){
    unsigned char buf[64];
    x.store(buf, nbytes);
    string s;
    s.resize(nbytes * 2);
    const char* hexd = "0123456789ABCDEF";
    for(int i = 0; i < nbytes; i++){
        s[2 * i]     = hexd[buf[i] >> 4];
        s[2 * i + 1] = hexd[buf[i] & 0xF];
    }
    return s;
}

class SHA256{
    static uint32_t rotr(uint32_t x, unsigned n){
        return (x >> n) | (x << (32u - n));
    }

    static uint32_t loadw(const unsigned char* p){
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }

    static void storew(unsigned char* p, uint32_t x){
        p[0] = (unsigned char)(x >> 24);
        p[1] = (unsigned char)(x >> 16);
        p[2] = (unsigned char)(x >> 8);
        p[3] = (unsigned char)x;
    }

    static void block(uint32_t h[8], const unsigned char b[64]){
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
        for(int i = 0; i < 16; i++)
            w[i] = loadw(b + 4 * i);
        for(int i = 16; i < 64; i++){
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for(int i = 0; i < 64; i++){
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
    static void hash(const unsigned char* data, int len, unsigned char out[32]){
        uint32_t h[8] = {
            0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
            0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
        };

        const unsigned char* p = data;
        int left = len;
        while(left >= 64){
            block(h, p);
            p += 64;
            left -= 64;
        }

        unsigned char buf[64];
        memset(buf, 0, 64);
        if(left && p)
            memcpy(buf, p, left);
        buf[left] = 0x80;

        uint64_t bits = (uint64_t)len * 8u;
        if(left >= 56){
            block(h, buf);
            memset(buf, 0, 64);
        }
        for(int i = 0; i < 8; i++)
            buf[63 - i] = (unsigned char)(bits >> (8 * i));
        block(h, buf);

        for(int i = 0; i < 8; i++)
            storew(out + 4 * i, h[i]);
    }
};

struct Point{
    Big X, Y, Z;
};

class Elliptic{
public:
    Big p, a, b, q, gx, gy;
    Numbers math;

    Elliptic(){
        fromhex(p,  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97");
        fromhex(a,  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94");
        fromhex(b,  "00000000000000000000000000000000000000000000000000000000000000A6");
        fromhex(q,  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893");
        fromhex(gx, "0000000000000000000000000000000000000000000000000000000000000001");
        fromhex(gy, "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14");
    }

    Big addf(Big x, Big y){
        x.add(y);
        x.mod(p);
        return x;
    }

    Big subf(Big x, Big y){
        x.sub(y);
        x.mod(p);
        return x;
    }

    Big mulf(Big x, Big y){
        x.mul(y);
        x.mod(p);
        return x;
    }

    Big invf(Big a){
        Big r;
        math.modInv(r, a, p);
        return r;
    }

    Point inf(){
        Point O;
        O.X.set(1);
        O.Y.set(1);
        O.Z.clear();
        return O;
    }

    Point G(){
        Point P;
        P.X = gx;
        P.Y = gy;
        P.Z.set(1);
        return P;
    }

    bool isInf(const Point& P){
        return P.Z.n == 0;
    }

    Point dbl(Point P){
        if(isInf(P))
            return P;

        Big Y2 = mulf(P.Y, P.Y);
        Big S  = mulf(Big(4), mulf(P.X, Y2));
        Big X2 = mulf(P.X, P.X);
        Big Z2 = mulf(P.Z, P.Z);
        Big Z4 = mulf(Z2, Z2);
        Big M  = addf(mulf(Big(3), X2), mulf(a, Z4));

        Point R;
        R.X = subf(mulf(M, M), mulf(Big(2), S));
        Big Y4 = mulf(Y2, Y2);
        R.Y = subf(mulf(M, subf(S, R.X)), mulf(Big(8), Y4));
        R.Z = mulf(Big(2), mulf(P.Y, P.Z));
        return R;
    }

    Point add(Point P, Point Q){
        if(isInf(P)) return Q;
        if(isInf(Q)) return P;

        Big Z1sq = mulf(P.Z, P.Z);
        Big Z2sq = mulf(Q.Z, Q.Z);
        Big U1 = mulf(P.X, Z2sq);
        Big U2 = mulf(Q.X, Z1sq);
        Big S1 = mulf(P.Y, mulf(Z2sq, Q.Z));
        Big S2 = mulf(Q.Y, mulf(Z1sq, P.Z));
        Big H  = subf(U2, U1);
        Big R  = subf(S2, S1);

        if(H.n == 0){
            if(R.n == 0)
                return dbl(P);
            return inf();
        }

        Big H2 = mulf(H, H);
        Big H3 = mulf(H2, H);

        Point T;
        T.X = subf(subf(mulf(R, R), H3), mulf(Big(2), mulf(U1, H2)));
        T.Y = subf(mulf(R, subf(mulf(U1, H2), T.X)), mulf(S1, H3));
        T.Z = mulf(H, mulf(P.Z, Q.Z));
        return T;
    }

    Point mul(Big k, Point P){
        if(k.s < 0)
            k.s = 1;
        Point R = inf();
        int nbits = k.bitlen();
        for(int i = nbits - 1; i >= 0; i--){
            R = dbl(R);
            if(k.bit(i))
                R = add(R, P);
        }
        return R;
    }

    Point toAffine(Point P){
        if(isInf(P))
            return inf();
        Big zi = invf(P.Z);
        Big zi2 = mulf(zi, zi);
        Big zi3 = mulf(zi2, zi);
        Point A;
        A.X = mulf(P.X, zi2);
        A.Y = mulf(P.Y, zi3);
        A.Z.set(1);
        return A;
    }

    bool onCurve(Point P){
        if(isInf(P))
            return true;
        P = toAffine(P);
        Big yy = mulf(P.Y, P.Y);
        Big xx = mulf(P.X, P.X);
        Big rhs = addf(addf(mulf(P.X, xx), mulf(a, P.X)), b);
        return yy.cmp(rhs) == 0;
    }
};

class ScalarBlind{
public:
    Elliptic& E;

    ScalarBlind(Elliptic& curve): E(curve){}

    Big randomScalar(){
        unsigned char buf[32];
        FILE* f = fopen("/dev/urandom", "rb");
        fread(buf, 1, 32, f);
        fclose(f);
        Big k;
        k.load(buf, 32);
        k.mod(E.q);
        if(k.n == 0)
            k.set(1);
        return k;
    }

    Big blind(const Big& d){
        unsigned char buf[8];
        FILE* f = fopen("/dev/urandom", "rb");
        fread(buf, 1, 8, f);
        fclose(f);
        Big r;
        r.load(buf, 8);
        if(r.n == 0)
            r.set(1);

        Big dp = d;
        Big rq = r;
        rq.mul(E.q);
        dp.add(rq);
        return dp;
    }

    Point multiply(const Big& d, const Point& P){
        Big dp = blind(d);
        return E.mul(dp, P);
    }
};

struct KeyPair{
    Big d;
    Point Q;
};

struct Signature{
    Big r;
    Big s;
};

class Gost3410{
public:
    Elliptic& E;
    ScalarBlind& ct;

    Gost3410(Elliptic& curve, ScalarBlind& blind): E(curve), ct(blind){}

    Big hashMsg(const unsigned char* m, int len){
        unsigned char h[32];
        SHA256::hash(m, len, h);
        Big e;
        e.load(h, 32);
        e.mod(E.q);
        if(e.n == 0)
            e.set(1);
        return e;
    }

    KeyPair keygen(){
        KeyPair kp;
        kp.d = ct.randomScalar();
        kp.Q = E.toAffine(ct.multiply(kp.d, E.G()));
        return kp;
    }

    Point ecdh(const Big& d, const Point& Qpeer){
        return E.toAffine(ct.multiply(d, Qpeer));
    }

    Signature sign(const Big& d, const unsigned char* m, int len){
        Big e = hashMsg(m, len);
        Signature sig;
        for(;;){
            Big k = ct.randomScalar();
            Point C = E.toAffine(ct.multiply(k, E.G()));
            sig.r = C.X;
            sig.r.mod(E.q);
            if(sig.r.n == 0)
                continue;

            sig.s = sig.r;
            sig.s.mul(d);
            Big ke = k;
            ke.mul(e);
            sig.s.add(ke);
            sig.s.mod(E.q);
            if(sig.s.n == 0)
                continue;
            break;
        }
        return sig;
    }

    bool verify(const Point& Q, const unsigned char* m, int len, Signature sig){
        if(sig.r.n == 0 || sig.r.cmp(E.q) >= 0) return false;
        if(sig.s.n == 0 || sig.s.cmp(E.q) >= 0) return false;

        Big e = hashMsg(m, len);
        Big v;
        if(!E.math.modInv(v, e, E.q))
            return false;

        Big z1 = sig.s;
        z1.mul(v);
        z1.mod(E.q);

        Big z2 = sig.r;
        z2.s = -1;
        z2.mul(v);
        z2.mod(E.q);

        Point C = E.toAffine(E.add(E.mul(z1, E.G()), E.mul(z2, Q)));
        if(E.isInf(C))
            return false;

        Big R = C.X;
        R.mod(E.q);
        return R.cmp(sig.r) == 0;
    }
};

int main(){
    Elliptic E;
    ScalarBlind ct(E);
    Gost3410 gost(E, ct);

    const char* msg = "au revoir, mon amour!";
    int n = (int)strlen(msg);

    KeyPair A = gost.keygen();
    KeyPair B = gost.keygen();

    cout << tohex(A.d, 32) << "\n";
    cout << tohex(A.Q.X, 32) << "\n";
    cout << tohex(A.Q.Y, 32) << "\n";
    cout << tohex(B.d, 32) << "\n";
    cout << tohex(B.Q.X, 32) << "\n";
    cout << tohex(B.Q.Y, 32) << "\n";

    Point KA = gost.ecdh(A.d, B.Q);
    Point KB = gost.ecdh(B.d, A.Q);
    cout << tohex(KA.X, 32) << "\n";
    cout << tohex(KB.X, 32) << "\n";
    cout << (KA.X.cmp(KB.X) == 0) << "\n";

    Signature sig = gost.sign(A.d, (const unsigned char*)msg, n);
    cout << tohex(sig.r, 32) << "\n";
    cout << tohex(sig.s, 32) << "\n";
    cout << gost.verify(A.Q, (const unsigned char*)msg, n, sig) << "\n";

    sig.s.add(Big(1));
    sig.s.mod(E.q);
    cout << gost.verify(A.Q, (const unsigned char*)msg, n, sig) << "\n";
}
