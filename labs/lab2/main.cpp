#include <iostream>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <x86intrin.h>
using namespace std;

const int KBYTES = 256;
const int HLEN = 48;
const int MAXMSG = KBYTES - 2 * HLEN - 2;
const int LIM = 68;

class Big{
public:
    unsigned long long d[LIM];
    int n;
    int s;

    Big(){
        clear();
    }

    Big(unsigned long v){
        clear();
        set(v);
    }

    void clear(){
        n = 0;
        s = 1;
        for(int i = 0; i < LIM; i++)
            d[i] = 0;
    }

    void set(unsigned long v){
        clear();
        if(v){
            d[0] = v;
            n = 1;
        }
    }

    void trim(){
        while(n > 0 && d[n - 1] == 0)
            n--;
        if(n == 0)
            s = 1;
    }

    int cmpAbs(const Big& o) const{
        if(n != o.n)
            return n > o.n ? 1 : -1;
        for(int i = n - 1; i >= 0; i--){
            if(d[i] != o.d[i])
                return d[i] > o.d[i] ? 1 : -1;
        }
        return 0;
    }

    int cmp(const Big& o) const{
        if(n == 0 && o.n == 0)
            return 0;
        if(s != o.s)
            return s;
        return s * cmpAbs(o);
    }

    int cmp(unsigned long v) const{
        Big t(v);
        return cmp(t);
    }

    void addAbs(const Big& o){
        unsigned long long c = 0;
        int m = n > o.n ? n : o.n;
        for(int i = 0; i < m; i++){
            unsigned long long a = i < n ? d[i] : 0;
            unsigned long long b = i < o.n ? o.d[i] : 0;
            unsigned long long s1 = a + b;
            unsigned long long c1 = s1 < a;
            unsigned long long s2 = s1 + c;
            unsigned long long c2 = s2 < s1;
            d[i] = s2;
            c = c1 | c2;
        }
        n = m;
        if(c)
            d[n++] = c;
    }

    void subAbs(const Big& o){
        unsigned long long b = 0;
        for(int i = 0; i < n; i++){
            unsigned long long x = d[i];
            unsigned long long y = i < o.n ? o.d[i] : 0;
            unsigned long long t = x - y;
            unsigned long long b1 = t > x;
            unsigned long long t2 = t - b;
            unsigned long long b2 = t2 > t;
            d[i] = t2;
            b = b1 | b2;
        }
        trim();
    }

    void add(const Big& o){
        if(s == o.s)
            addAbs(o);
        else if(cmpAbs(o) >= 0)
            subAbs(o);
        else{
            Big t = o;
            t.subAbs(*this);
            *this = t;
        }
        trim();
    }

    void sub(const Big& o){
        Big t = o;
        t.s = -t.s;
        if(t.n == 0)
            t.s = 1;
        add(t);
    }

    void mul(const Big& o){
        unsigned long long t[LIM];
        for(int i = 0; i < LIM; i++)
            t[i] = 0;
        int sign = s * o.s;
        for(int i = 0; i < n; i++){
            unsigned long long carry = 0;
            for(int j = 0; j < o.n; j++){
                __uint128_t p = (__uint128_t)d[i] * o.d[j] + t[i + j] + carry;
                t[i + j] = (unsigned long long)p;
                carry = (unsigned long long)(p >> 64);
            }
            int k = i + o.n;
            while(carry){
                __uint128_t p = (__uint128_t)t[k] + carry;
                t[k] = (unsigned long long)p;
                carry = (unsigned long long)(p >> 64);
                k++;
            }
        }
        n = n + o.n + 1;
        if(n > LIM)
            n = LIM;
        for(int i = 0; i < LIM; i++)
            d[i] = t[i];
        s = sign;
        trim();
    }

    unsigned long long divLimb(unsigned long long v){
        __uint128_t r = 0;
        for(int i = n - 1; i >= 0; i--){
            r = (r << 64) | d[i];
            d[i] = (unsigned long long)(r / v);
            r %= v;
        }
        trim();
        return (unsigned long long)r;
    }

    void shlBits(int k){
        if(n == 0 || k <= 0)
            return;
        int limbs = k / 64;
        int bits = k % 64;
        if(limbs){
            for(int i = n - 1; i >= 0; i--){
                if(i + limbs < LIM)
                    d[i + limbs] = d[i];
            }
            for(int i = 0; i < limbs; i++)
                d[i] = 0;
            n += limbs;
            if(n > LIM)
                n = LIM;
        }
        if(bits){
            unsigned long long carry = 0;
            for(int i = 0; i < n; i++){
                unsigned long long x = d[i];
                d[i] = (x << bits) | carry;
                carry = x >> (64 - bits);
            }
            if(carry && n < LIM)
                d[n++] = carry;
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
            d[i] = d[i + limbs];
        for(int i = n - limbs; i < n; i++)
            d[i] = 0;
        n -= limbs;
        if(bits){
            unsigned long long carry = 0;
            for(int i = n - 1; i >= 0; i--){
                unsigned long long x = d[i];
                d[i] = (x >> bits) | carry;
                carry = x << (64 - bits);
            }
        }
        trim();
    }

    static unsigned long long submul(unsigned long long* r, const unsigned long long* m, int dn, unsigned long long q){
        unsigned long long carry = 0;
        for(int i = 0; i < dn; i++){
            __uint128_t p = (__uint128_t)m[i] * q + carry;
            unsigned long long plo = (unsigned long long)p;
            carry = (unsigned long long)(p >> 64);
            unsigned long long t = r[i];
            unsigned long long s1 = t - plo;
            if(s1 > t)
                carry++;
            r[i] = s1;
        }
        return carry;
    }

    static unsigned long long addn(unsigned long long* r, const unsigned long long* m, int dn){
        unsigned long long c = 0;
        for(int i = 0; i < dn; i++){
            unsigned long long s1 = r[i] + m[i];
            unsigned long long c1 = s1 < r[i];
            unsigned long long s2 = s1 + c;
            unsigned long long c2 = s2 < s1;
            r[i] = s2;
            c = c1 | c2;
        }
        return c;
    }

    void divmod(Big& q, Big& r, const Big& den) const{
        Big u = *this;
        Big v = den;
        int us = u.s;
        int vs = v.s;
        u.s = 1;
        v.s = 1;
        q.clear();
        r.clear();
        if(v.n == 0)
            return;
        if(u.n == 0)
            return;
        if(u.cmpAbs(v) < 0){
            r = u;
            r.s = us;
            if(r.n == 0)
                r.s = 1;
            return;
        }
        if(v.n == 1){
            q = u;
            unsigned long long rem = q.divLimb(v.d[0]);
            r.set(rem);
            q.s = us * vs;
            r.s = us;
            q.trim();
            r.trim();
            return;
        }

        int shift = __builtin_clzll(v.d[v.n - 1]);
        u.shlBits(shift);
        v.shlBits(shift);
        if(u.n < LIM)
            u.d[u.n] = 0;
        int vn = v.n;
        int un = u.n;
        q.n = un - vn + 1;
        for(int i = 0; i < LIM; i++)
            q.d[i] = 0;

        for(int j = un - vn; j >= 0; j--){
            __uint128_t num = ((__uint128_t)u.d[j + vn] << 64) | u.d[j + vn - 1];
            unsigned long long qhat;
            unsigned long long rhat;
            if(u.d[j + vn] == v.d[vn - 1]){
                qhat = ~0ull;
                rhat = (unsigned long long)(num - (__uint128_t)qhat * v.d[vn - 1]);
            }else{
                qhat = (unsigned long long)(num / v.d[vn - 1]);
                rhat = (unsigned long long)(num % v.d[vn - 1]);
            }
            while((__uint128_t)qhat * v.d[vn - 2] > (((__uint128_t)rhat << 64) | u.d[j + vn - 2])){
                qhat--;
                unsigned long long old = rhat;
                rhat += v.d[vn - 1];
                if(rhat < old)
                    break;
            }
            unsigned long long br = submul(u.d + j, v.d, vn, qhat);
            if(u.d[j + vn] < br){
                qhat--;
                addn(u.d + j, v.d, vn);
                u.d[j + vn] += 1;
            }
            u.d[j + vn] -= br;
            q.d[j] = qhat;
        }
        q.trim();
        r = u;
        r.n = vn + 1;
        r.shrBits(shift);
        r.trim();
        q.s = us * vs;
        r.s = us;
        if(q.n == 0)
            q.s = 1;
        if(r.n == 0)
            r.s = 1;
    }

    void mod(const Big& m){
        Big q, r;
        divmod(q, r, m);
        if(r.s < 0 && r.n){
            r.s = 1;
            Big t = m;
            t.s = 1;
            t.sub(r);
            r = t;
        }
        r.s = 1;
        *this = r;
    }

    unsigned long modSmall(unsigned long v) const{
        __uint128_t r = 0;
        for(int i = n - 1; i >= 0; i--)
            r = (((r << 64) | d[i]) % v);
        return (unsigned long)r;
    }

    int bitlen() const{
        if(n == 0)
            return 0;
        return (n - 1) * 64 + (64 - __builtin_clzll(d[n - 1]));
    }

    int bit(int i) const{
        int limb = i / 64;
        int off = i % 64;
        if(limb >= n)
            return 0;
        return (int)((d[limb] >> off) & 1ull);
    }

    void setBit(int i){
        int limb = i / 64;
        int off = i % 64;
        if(limb >= LIM)
            return;
        d[limb] |= 1ull << off;
        if(limb + 1 > n)
            n = limb + 1;
    }

    int even() const{
        return n == 0 || (d[0] & 1ull) == 0;
    }

    unsigned long low() const{
        return n ? (unsigned long)d[0] : 0;
    }

    void load(const unsigned char* in, int k){
        clear();
        if(k <= 0)
            return;
        n = (k + 7) / 8;
        if(n > LIM)
            n = LIM;
        for(int i = 0; i < k; i++){
            int idx = k - 1 - i;
            int limb = idx / 8;
            int off = (idx % 8) * 8;
            if(limb < LIM)
                d[limb] |= (unsigned long long)in[i] << off;
        }
        trim();
    }

    void store(unsigned char* out, int k) const{
        memset(out, 0, k);
        for(int i = 0; i < k; i++){
            int idx = k - 1 - i;
            int limb = idx / 8;
            int off = (idx % 8) * 8;
            if(limb < n)
                out[i] = (unsigned char)(d[limb] >> off);
        }
    }

    void cswap(Big& o, unsigned bit){
        unsigned long long mask = 0ull - (unsigned long long)(bit & 1);
        for(int i = 0; i < LIM; i++){
            unsigned long long t = (d[i] ^ o.d[i]) & mask;
            d[i] ^= t;
            o.d[i] ^= t;
        }
        int im = (int)mask;
        int tn = (n ^ o.n) & im;
        n ^= tn;
        o.n ^= tn;
        int ts = (s ^ o.s) & im;
        s ^= ts;
        o.s ^= ts;
    }
};

bool fillRandom(unsigned char* buf, int n){
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0)
        return false;
    int off = 0;
    while(off < n){
        int got = read(fd, buf + off, n - off);
        if(got <= 0){
            close(fd);
            return false;
        }
        off += got;
    }
    close(fd);
    return true;
}

void show(const char* name, const Big& x){
    if(x.n == 0){
        cout << "  " << name << " = 0\n";
        return;
    }
    Big t = x;
    char dig[700];
    int k = 0;
    int neg = t.s < 0;
    t.s = 1;
    if(t.n == 0){
        cout << "  " << name << " = 0\n";
        return;
    }
    while(t.n){
        unsigned long long r = t.divLimb(10);
        dig[k++] = (char)('0' + (int)r);
    }
    cout << "  " << name << " = ";
    if(neg)
        cout << "-";
    for(int i = k - 1; i >= 0; i--)
        cout << dig[i];
    cout << "\n";
}

class Numbers{

    bool smallFactor(const Big& n){
        static const unsigned p[] = {
            3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,
            101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,
            211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,
            331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,
            457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,
            599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,
            733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,
            877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997
        };
        for(unsigned prime : p){
            if(n.cmp((unsigned long)prime) == 0)
                return false;
            if(n.modSmall(prime) == 0)
                return true;
        }
        return false;
    }

    bool randomOdd(Big& r, int bits){
        int nbytes = (bits + 7) / 8;
        unsigned char buf[512];
        if(!fillRandom(buf, nbytes))
            return false;
        int extra = nbytes * 8 - bits;
        if(extra)
            buf[0] &= (unsigned char)(0xFFu >> extra);
        r.load(buf, nbytes);
        r.setBit(bits - 1);
        r.setBit(bits - 2);
        r.setBit(0);
        return true;
    }

public:

    void gcd(Big& g, const Big& a, const Big& b){
        Big u = a;
        Big v = b;
        u.s = 1;
        v.s = 1;
        while(v.n){
            Big q, r;
            u.divmod(q, r, v);
            u = v;
            v = r;
        }
        g = u;
        g.s = 1;
    }

    void egcd(Big& g, Big& x, Big& y, const Big& a, const Big& b){
        Big oldR = a;
        Big r = b;
        Big oldS(1), s(0), oldT(0), t(1);
        while(r.n){
            Big q, nr;
            oldR.divmod(q, nr, r);

            Big tmp = q;
            tmp.mul(s);
            Big ns = oldS;
            ns.sub(tmp);

            tmp = q;
            tmp.mul(t);
            Big nt = oldT;
            nt.sub(tmp);

            oldR = r;
            r = nr;
            oldS = s;
            s = ns;
            oldT = t;
            t = nt;
        }
        g = oldR;
        x = oldS;
        y = oldT;
    }

    bool modInv(Big& r, const Big& a, const Big& m){
        Big g, x, y;
        egcd(g, x, y, a, m);
        if(g.cmp(1ul) != 0)
            return false;
        r = x;
        r.mod(m);
        return true;
    }

    void lcm(Big& r, const Big& a, const Big& b){
        Big g, prod = a;
        prod.s = 1;
        Big bb = b;
        bb.s = 1;
        gcd(g, prod, bb);
        prod.mul(bb);
        Big q, rem;
        prod.divmod(q, rem, g);
        r = q;
        r.s = 1;
    }

    void modPow(Big& r, const Big& base, const Big& exp, const Big& modulo, int nbits){
        if(nbits <= 0 || modulo.cmp(1ul) == 0){
            r.set(modulo.cmp(1ul) == 0 ? 0 : 1);
            return;
        }
        Big r0(1), r1 = base;
        r1.mod(modulo);
        for(int k = nbits; k > 0; k--){
            unsigned bit = (unsigned)exp.bit(k - 1);
            r0.cswap(r1, bit);
            Big tmp = r0;
            tmp.mul(r1);
            tmp.mod(modulo);
            r1 = tmp;
            tmp = r0;
            tmp.mul(r0);
            tmp.mod(modulo);
            r0 = tmp;
            r0.cswap(r1, bit);
        }
        r = r0;
    }

    void modPowSlow(Big& r, const Big& base, const Big& exp, const Big& modulo, int nbits){
        if(nbits <= 0 || modulo.cmp(1ul) == 0){
            r.set(modulo.cmp(1ul) == 0 ? 0 : 1);
            return;
        }
        Big result(1), b = base;
        b.mod(modulo);
        for(int k = nbits; k > 0; k--){
            result.mul(result);
            result.mod(modulo);
            if(exp.bit(k - 1)){
                result.mul(b);
                result.mod(modulo);
            }
        }
        r = result;
    }

    bool millerRabin(const Big& n, int rounds){
        if(n.cmp(2ul) < 0)
            return false;
        if(n.cmp(2ul) == 0 || n.cmp(3ul) == 0)
            return true;
        if(n.even())
            return false;

        Big nm1 = n;
        Big one(1);
        nm1.sub(one);
        Big d = nm1;
        int s = 0;
        while(d.even()){
            d.shrBits(1);
            s++;
        }
        Big n3 = n;
        Big three(3);
        n3.sub(three);
        int nbytes = (n.bitlen() + 7) / 8;
        if(nbytes <= 0 || nbytes > 512)
            return false;
        unsigned char buf[512];

        for(int round = 0; round < rounds; round++){
            if(!fillRandom(buf, nbytes))
                return false;
            Big a;
            a.load(buf, nbytes);
            a.mod(n3);
            Big two(2);
            a.add(two);
            int dbits = d.bitlen();
            if(dbits == 0)
                dbits = 1;
            Big x;
            modPowSlow(x, a, d, n, dbits);
            if(x.cmp(1ul) == 0 || x.cmp(nm1) == 0)
                continue;
            int strong = 0;
            for(int r = 1; r < s; r++){
                x.mul(x);
                x.mod(n);
                if(x.cmp(nm1) == 0){
                    strong = 1;
                    break;
                }
                if(x.cmp(1ul) == 0)
                    return false;
            }
            if(!strong)
                return false;
        }
        return true;
    }

    bool randomPrime(Big& p, int bits, int rounds){
        for(int tries = 1; tries <= 200000; tries++){
            if(!randomOdd(p, bits))
                return false;
            if(smallFactor(p))
                continue;
            if(millerRabin(p, rounds)){
                cout << "  простое " << bits << " бит, попытка " << tries << "\n";
                return true;
            }
        }
        return false;
    }

    void os2ip(Big& x, const unsigned char* in, int k){
        x.load(in, k);
    }

    void i2osp(const Big& x, unsigned char* out, int k){
        x.store(out, k);
    }
};

class Rsa{
    Numbers math;

public:
    Big n, e, d, p, q, dp, dq, qinv;

    bool generate(int bits){
        int pbits = bits / 2;
        e.set(65537ul);
        for(int outer = 0; outer < 8; outer++){
            if(!math.randomPrime(p, pbits, 16))
                return false;
            if(p.modSmall(65537ul) == 1)
                continue;
            for(int qtry = 0; qtry < 6; qtry++){
                if(!math.randomPrime(q, pbits, 16))
                    return false;
                if(p.cmp(q) == 0 || q.modSmall(65537ul) == 1)
                    continue;
                n = p;
                n.mul(q);
                if(n.bitlen() < bits)
                    continue;

                Big pm1 = p;
                Big qm1 = q;
                Big one(1);
                pm1.sub(one);
                qm1.sub(one);
                Big lambda, g;
                math.lcm(lambda, pm1, qm1);
                math.gcd(g, e, lambda);
                if(g.cmp(1ul) != 0)
                    break;
                if(!math.modInv(d, e, lambda))
                    return false;
                dp = d;
                dp.mod(pm1);
                dq = d;
                dq.mod(qm1);
                if(!math.modInv(qinv, q, p))
                    return false;
                return true;
            }
        }
        return false;
    }

    void encrypt(Big& c, const Big& m){
        int window = e.bitlen();
        math.modPow(c, m, e, n, window);
    }

    void decrypt(Big& m, const Big& c){
        Big m1, m2, h;
        math.modPow(m1, c, dp, p, p.bitlen());
        math.modPow(m2, c, dq, q, q.bitlen());
        Big diff = m1;
        diff.sub(m2);
        diff.mul(qinv);
        h = diff;
        h.mod(p);
        m = h;
        m.mul(q);
        m.add(m2);
    }

    void decryptSlow(Big& m, const Big& c){
        math.modPow(m, c, d, n, n.bitlen());
    }

    bool encryptBytes(unsigned char* ct, unsigned char* em){
        Big m, c;
        math.os2ip(m, em, KBYTES);
        if(m.cmp(n) >= 0)
            return false;
        encrypt(c, m);
        math.i2osp(c, ct, KBYTES);
        return true;
    }

    bool decryptBytes(unsigned char* em, unsigned char* ct){
        Big c, m;
        math.os2ip(c, ct, KBYTES);
        if(c.cmp(n) >= 0)
            return false;
        decrypt(m, c);
        math.i2osp(m, em, KBYTES);
        return true;
    }
};

class Oaep{
    Rsa& rsa;

    static const unsigned long long Kt[80];

    static unsigned long long rotr(unsigned long long x, int n){
        return (x >> n) | (x << (64 - n));
    }

    void process(unsigned long long h[8], const unsigned char block[128]){
        unsigned long long w[80];
        for(int i = 0; i < 16; i++){
            w[i] = 0;
            for(int j = 0; j < 8; j++)
                w[i] = (w[i] << 8) | block[8 * i + j];
        }
        for(int i = 16; i < 80; i++){
            unsigned long long s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
            unsigned long long s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
            w[i] = s1 + w[i - 7] + s0 + w[i - 16];
        }
        unsigned long long a = h[0], b = h[1], c = h[2], d = h[3];
        unsigned long long e = h[4], f = h[5], g = h[6], hh = h[7];
        for(int i = 0; i < 80; i++){
            unsigned long long S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
            unsigned long long ch = (e & f) ^ (~e & g);
            unsigned long long t1 = hh + S1 + ch + Kt[i] + w[i];
            unsigned long long S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
            unsigned long long maj = (a & b) ^ (a & c) ^ (b & c);
            unsigned long long t2 = S0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    void sha384(const unsigned char* data, int len, unsigned char out[48]){
        unsigned long long h[8] = {
            0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
            0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
        };
        const unsigned char* p = data;
        int n = len;
        while(n >= 128){
            process(h, p);
            p += 128;
            n -= 128;
        }
        unsigned char block[128];
        memset(block, 0, 128);
        if(n > 0)
            memcpy(block, p, n);
        block[n] = 0x80;
        if(n >= 112){
            process(h, block);
            memset(block, 0, 128);
        }
        unsigned long long bits = (unsigned long long)len * 8ull;
        for(int i = 0; i < 8; i++)
            block[127 - i] = (unsigned char)(bits >> (8 * i));
        process(h, block);
        for(int i = 0; i < 6; i++){
            for(int j = 0; j < 8; j++)
                out[8 * i + j] = (unsigned char)(h[i] >> (56 - 8 * j));
        }
    }

    void mgf1(unsigned char* seed, int seedLen, unsigned char* mask, int maskLen){
        unsigned char block[KBYTES + 4];
        unsigned char digest[HLEN];
        int offset = 0;
        unsigned counter = 0;
        while(offset < maskLen){
            if(seedLen > 0)
                memcpy(block, seed, seedLen);
            block[seedLen]     = (unsigned char)(counter >> 24);
            block[seedLen + 1] = (unsigned char)(counter >> 16);
            block[seedLen + 2] = (unsigned char)(counter >> 8);
            block[seedLen + 3] = (unsigned char)counter;
            sha384(block, seedLen + 4, digest);
            int room = maskLen - offset;
            int take = room < HLEN ? room : HLEN;
            memcpy(mask + offset, digest, take);
            offset += take;
            counter++;
        }
    }

    unsigned char nzMask(unsigned char x){
        unsigned int v = x;
        v = (v | (0u - v)) >> 31;
        return (unsigned char)(0u - v);
    }

    unsigned char eqMask(unsigned char a, unsigned char b){
        return (unsigned char)(~nzMask((unsigned char)(a ^ b)));
    }

    unsigned char eq16(unsigned short a, unsigned short b){
        unsigned int x = (unsigned int)(a ^ b);
        x = (x - 1u) >> 31;
        return (unsigned char)(0u - x);
    }

    unsigned short pick(unsigned char mask, unsigned short a, unsigned short b){
        unsigned short m = (unsigned short)(short)(signed char)mask;
        return (unsigned short)((m & a) | ((unsigned short)~m & b));
    }

    void scanOne(unsigned char* db, int dbLen, unsigned char& found, unsigned short& oneIdx, unsigned char& psErr){
        found = 0;
        oneIdx = 0;
        psErr = 0;
        for(int i = HLEN; i < dbLen; i++){
            unsigned char isOne = eqMask(db[i], 0x01);
            unsigned char isZero = eqMask(db[i], 0x00);
            unsigned char looking = (unsigned char)~found;
            unsigned char bad = (unsigned char)(looking & (unsigned char)~isZero & (unsigned char)~isOne);
            psErr = (unsigned char)(psErr | bad);
            unsigned char take = (unsigned char)(looking & isOne);
            oneIdx = pick(take, (unsigned short)i, oneIdx);
            found = (unsigned char)(found | take);
        }
    }

public:

    Oaep(Rsa& r): rsa(r){}

    bool shaOk(){
        unsigned char out[48];
        sha384(0, 0, out);
        unsigned char emptyH[48] = {
            0x38,0xb0,0x60,0xa7,0x51,0xac,0x96,0x38,0x4c,0xd9,0x32,0x7e,0xb1,0xb1,0xe3,0x6a,
            0x21,0xfd,0xb7,0x11,0x14,0xbe,0x07,0x43,0x4c,0x0c,0xc7,0xbf,0x63,0xf6,0xe1,0xda,
            0x27,0x4e,0xde,0xbf,0xe7,0x6f,0x65,0xfb,0xd5,0x1a,0xd2,0xf1,0x48,0x98,0xb9,0x5b
        };
        unsigned char acc = 0;
        for(int i = 0; i < 48; i++)
            acc = (unsigned char)(acc | (out[i] ^ emptyH[i]));
        unsigned char abc[3] = {'a','b','c'};
        unsigned char abcOut[48];
        sha384(abc, 3, abcOut);
        unsigned char abcH[48] = {
            0xcb,0x00,0x75,0x3f,0x45,0xa3,0x5e,0x8b,0xb5,0xa0,0x3d,0x69,0x9a,0xc6,0x50,0x07,
            0x27,0x2c,0x32,0xab,0x0e,0xde,0xd1,0x63,0x1a,0x8b,0x60,0x5a,0x43,0xff,0x5b,0xed,
            0x80,0x86,0x07,0x2b,0xa1,0xe7,0xcc,0x23,0x58,0xba,0xec,0xa1,0x34,0xc8,0x25,0xa7
        };
        for(int i = 0; i < 48; i++)
            acc = (unsigned char)(acc | (abcOut[i] ^ abcH[i]));
        return acc == 0;
    }

    bool encode(unsigned char em[KBYTES], unsigned char* msg, int mlen){
        if(mlen < 0 || mlen > MAXMSG)
            return false;
        int dbLen = KBYTES - HLEN - 1;
        int psLen = KBYTES - mlen - 2 * HLEN - 2;

        unsigned char lHash[HLEN];
        sha384(0, 0, lHash);

        unsigned char db[KBYTES];
        memcpy(db, lHash, HLEN);
        memset(db + HLEN, 0x00, psLen);
        db[HLEN + psLen] = 0x01;
        if(mlen > 0)
            memcpy(db + HLEN + psLen + 1, msg, mlen);

        unsigned char seed[HLEN];
        if(!fillRandom(seed, HLEN))
            return false;

        unsigned char dbMask[KBYTES];
        unsigned char maskedDB[KBYTES];
        mgf1(seed, HLEN, dbMask, dbLen);
        for(int i = 0; i < dbLen; i++)
            maskedDB[i] = (unsigned char)(db[i] ^ dbMask[i]);

        unsigned char seedMask[HLEN];
        mgf1(maskedDB, dbLen, seedMask, HLEN);

        em[0] = 0x00;
        for(int i = 0; i < HLEN; i++)
            em[1 + i] = (unsigned char)(seed[i] ^ seedMask[i]);
        memcpy(em + 1 + HLEN, maskedDB, dbLen);
        return true;
    }

    bool decode(unsigned char* msg, int* mlen, unsigned char em[KBYTES]){
        int dbLen = KBYTES - HLEN - 1;
        unsigned char lHash[HLEN];
        sha384(0, 0, lHash);

        unsigned char error = nzMask(em[0]);

        unsigned char maskedSeed[HLEN];
        unsigned char maskedDB[KBYTES];
        memcpy(maskedSeed, em + 1, HLEN);
        memcpy(maskedDB, em + 1 + HLEN, dbLen);

        unsigned char seedMask[HLEN];
        unsigned char seed[HLEN];
        mgf1(maskedDB, dbLen, seedMask, HLEN);
        for(int i = 0; i < HLEN; i++)
            seed[i] = (unsigned char)(maskedSeed[i] ^ seedMask[i]);

        unsigned char dbMask[KBYTES];
        unsigned char db[KBYTES];
        mgf1(seed, HLEN, dbMask, dbLen);
        for(int i = 0; i < dbLen; i++)
            db[i] = (unsigned char)(maskedDB[i] ^ dbMask[i]);

        unsigned char lacc = 0;
        for(int i = 0; i < HLEN; i++)
            lacc = (unsigned char)(lacc | (db[i] ^ lHash[i]));
        error = (unsigned char)(error | nzMask(lacc));

        unsigned char found = 0;
        unsigned short oneIdx = 0;
        unsigned char psErr = 0;
        scanOne(db, dbLen, found, oneIdx, psErr);
        error = (unsigned char)(error | (unsigned char)~found | psErr);

        unsigned char extracted[MAXMSG];
        for(int j = 0; j < MAXMSG; j++){
            unsigned char b = 0;
            unsigned short want = (unsigned short)(oneIdx + 1 + j);
            for(int i = 0; i < dbLen; i++){
                unsigned char match = eq16((unsigned short)i, want);
                b = (unsigned char)(b | (db[i] & match));
            }
            extracted[j] = b;
        }

        unsigned char ok = (unsigned char)~nzMask(error);
        int cand = (dbLen - 1) - (int)oneIdx;
        int outLen = cand & (int)(signed char)ok;

        if(msg){
            for(int j = 0; j < MAXMSG; j++)
                msg[j] = (unsigned char)(extracted[j] & ok);
        }
        if(mlen)
            *mlen = outLen;
        return ok == 0xFF;
    }

    bool seal(unsigned char* msg, int mlen, unsigned char* ct){
        unsigned char em[KBYTES];
        if(!encode(em, msg, mlen))
            return false;
        bool ok = rsa.encryptBytes(ct, em);
        memset(em, 0, KBYTES);
        return ok;
    }

    bool open(unsigned char* ct, unsigned char* msg, int* mlen){
        unsigned char em[KBYTES];
        if(!rsa.decryptBytes(em, ct))
            return false;
        bool ok = decode(msg, mlen, em);
        memset(em, 0, KBYTES);
        return ok;
    }
};

const unsigned long long Oaep::Kt[80] = {
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
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

unsigned long long ticks(){
    unsigned aux;
    return __rdtscp(&aux);
}

void demoSmall(Numbers& math){
    Big p(61), q(53), n = p, e(17), d, pm1, qm1, lambda, g;
    n.mul(q);
    pm1 = p;
    qm1 = q;
    Big one(1);
    pm1.sub(one);
    qm1.sub(one);
    math.lcm(lambda, pm1, qm1);
    math.gcd(g, e, lambda);
    math.modInv(d, e, lambda);

    Big dp = d, dq = d, qinv;
    dp.mod(pm1);
    dq.mod(qm1);
    math.modInv(qinv, q, p);

    Big m(65), c, m1, m2, h, back, slow;
    math.modPow(c, m, e, n, e.bitlen());
    math.modPow(m1, c, dp, p, p.bitlen());
    math.modPow(m2, c, dq, q, q.bitlen());
    Big diff = m1;
    diff.sub(m2);
    h = diff;
    h.mul(qinv);
    h.mod(p);
    back = h;
    back.mul(q);
    back.add(m2);
    math.modPow(slow, c, d, n, n.bitlen());

    show("p", p);
    show("q", q);
    show("N", n);
    show("lambda", lambda);
    show("d", d);
    show("dp", dp);
    show("dq", dq);
    show("qinv", qinv);
    show("c", c);
    show("m1", m1);
    show("m2", m2);
    show("h", h);
    show("гарнер", back);
    cout << (back.cmp(m) == 0 && slow.cmp(m) == 0) << "\n";
}

void setExp(Big& e, int nbits, int mode){
    e.clear();
    for(int i = 0; i < nbits; i++){
        int on = 0;
        if(mode == 0)
            on = (i + 1 == nbits);
        else if(mode == 1)
            on = (i % 2 == 0);
        else
            on = 1;
        if(on)
            e.setBit(i);
    }
    e.setBit(nbits - 1);
}

void demoLadder(Numbers& math){
    const int bits = 256;
    const int reps = 4;
    Big mod, base(3), exps[3];
    mod.setBit(bits - 1);
    mod.setBit(0);
    for(int i = 1; i < bits - 1; i += 3)
        mod.setBit(i);
    for(int mode = 0; mode < 3; mode++)
        setExp(exps[mode], bits, mode);

    unsigned long long ladder[3] = {0, 0, 0};
    unsigned long long binary[3] = {0, 0, 0};
    volatile unsigned long sink = 0;
    for(int rep = 0; rep < reps; rep++){
        for(int mode = 0; mode < 3; mode++){
            Big out;
            unsigned long long c0 = ticks();
            math.modPow(out, base, exps[mode], mod, bits);
            unsigned long long c1 = ticks();
            sink ^= out.low();
            ladder[mode] += c1 - c0;

            c0 = ticks();
            math.modPowSlow(out, base, exps[mode], mod, bits);
            c1 = ticks();
            sink ^= out.low();
            binary[mode] += c1 - c0;
        }
    }
    (void)sink;
    cout << "лестница";
    for(int mode = 0; mode < 3; mode++)
        cout << " " << ladder[mode] / reps;
    cout << "\nдвоичный";
    for(int mode = 0; mode < 3; mode++)
        cout << " " << binary[mode] / reps;
    cout << "\n";
}

int main(){
    Numbers math;
    Rsa rsa;
    Oaep oaep(rsa);

    cout << oaep.shaOk() << "\n";
    demoSmall(math);
    demoLadder(math);

    cout << "ключ...\n";
    if(!rsa.generate(2048)){
        cout << "0\n";
        return 1;
    }
    cout << "|N| = " << rsa.n.bitlen() << "\n";

    unsigned long samples[2] = {0, 42};
    for(int i = 0; i < 2; i++){
        Big m(samples[i]), c, back, slow;
        rsa.encrypt(c, m);
        rsa.decrypt(back, c);
        rsa.decryptSlow(slow, c);
        cout << (back.cmp(m) == 0 && slow.cmp(m) == 0) << "\n";
    }

    unsigned char emptyCt[KBYTES];
    unsigned char emptyBack[MAXMSG];
    int emptyLen = -1;
    bool emptyOk = oaep.seal(0, 0, emptyCt) && oaep.open(emptyCt, emptyBack, &emptyLen) && emptyLen == 0;
    cout << emptyOk << "\n";

    unsigned char maxMsg[MAXMSG];
    unsigned char maxCt[KBYTES];
    unsigned char maxBack[MAXMSG];
    int maxLen = 0;
    memset(maxMsg, 0x5c, MAXMSG);
    bool maxOk = oaep.seal(maxMsg, MAXMSG, maxCt) && oaep.open(maxCt, maxBack, &maxLen)
        && maxLen == MAXMSG && memcmp(maxMsg, maxBack, MAXMSG) == 0;
    cout << maxOk << "\n";

    unsigned char p[5] = {'h','e','l','l','o'};
    unsigned char c[KBYTES];
    unsigned char c2[KBYTES];
    unsigned char back[MAXMSG];
    int backLen = 0;
    oaep.seal(p, 5, c);
    oaep.seal(p, 5, c2);
    cout << (memcmp(c, c2, KBYTES) != 0) << "\n";
    bool ok = oaep.open(c, back, &backLen);

    unsigned char bad[KBYTES];
    memcpy(bad, c, KBYTES);
    if(bad[KBYTES - 1] > 0)
        bad[KBYTES - 1]--;
    else
        bad[KBYTES - 1] ^= 1;
    int badLen = -1;
    bool badOk = oaep.open(bad, back, &badLen);
    cout << (!badOk && badLen == 0) << "\n";

    const int reps = 2;
    unsigned long long okSum = 0;
    unsigned long long badSum = 0;
    unsigned long long crtSum = 0;
    unsigned long long slowSum = 0;
    Big cipher, plain;
    Numbers bytes;
    bytes.os2ip(cipher, c, KBYTES);
    volatile unsigned sink = 0;
    for(int i = 0; i < reps; i++){
        unsigned long long t0 = ticks();
        bool vok = oaep.open(c, back, &backLen);
        unsigned long long t1 = ticks();
        sink ^= vok ? back[0] : 0;
        okSum += t1 - t0;

        t0 = ticks();
        bool vbad = oaep.open(bad, back, &badLen);
        t1 = ticks();
        sink ^= vbad ? 1 : 0;
        badSum += t1 - t0;

        t0 = ticks();
        rsa.decrypt(plain, cipher);
        t1 = ticks();
        sink ^= (unsigned)plain.low();
        crtSum += t1 - t0;

        t0 = ticks();
        rsa.decryptSlow(plain, cipher);
        t1 = ticks();
        sink ^= (unsigned)plain.low();
        slowSum += t1 - t0;
    }
    (void)sink;
    cout << "верный " << okSum / reps << "\n";
    cout << "порченый " << badSum / reps << "\n";
    cout << "crt " << crtSum / reps << "\n";
    cout << "прямо " << slowSum / reps << "\n";

    ok = oaep.open(c, back, &backLen);
    cout << ok << "\n";
    for(int i = 0; i < backLen; i++)
        cout << (char)back[i];
    cout << "\n";
    return ok ? 0 : 1;
}
