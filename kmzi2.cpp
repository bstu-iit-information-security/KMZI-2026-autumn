#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <random>
#include <stdexcept>
#include <algorithm>

using std::vector;
using std::string;
using std::cout;
using std::cerr;
using std::endl;
using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i32 = int32_t;
using i64 = int64_t;

namespace sha512_ns {

static const u64 K[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static inline u64 rotr(u64 x, int n) { return (x >> n) | (x << (64 - n)); }

static void process_block(u64 h[8], const u8* block) {
    u64 w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = 0;
        for (int j = 0; j < 8; ++j) w[i] = (w[i] << 8) | block[i*8 + j];
    }
    for (int i = 16; i < 80; ++i) {
        u64 s0 = rotr(w[i-15], 1) ^ rotr(w[i-15], 8) ^ (w[i-15] >> 7);
        u64 s1 = rotr(w[i-2], 19) ^ rotr(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    u64 a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 80; ++i) {
        u64 S1 = rotr(e,14) ^ rotr(e,18) ^ rotr(e,41);
        u64 ch = (e & f) ^ ((~e) & g);
        u64 t1 = hh + S1 + ch + K[i] + w[i];
        u64 S0 = rotr(a,28) ^ rotr(a,34) ^ rotr(a,39);
        u64 mj = (a & b) ^ (a & c) ^ (b & c);
        u64 t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

vector<u8> hash(const vector<u8>& data) {
    u64 h[8] = {
        0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL
    };
    vector<u8> msg = data;
    u64 bitLen = (u64)data.size() * 8;
    msg.push_back(0x80);
    while (msg.size() % 128 != 112) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i) msg.push_back((u8)((bitLen >> (i*8)) & 0xFF));
    for (int i = 7; i >= 0; --i) msg.push_back(0x00);

    for (size_t off = 0; off < msg.size(); off += 128)
        process_block(h, msg.data() + off);

    vector<u8> out(64);
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 8; ++j)
            out[i*8 + j] = (u8)((h[i] >> (56 - j*8)) & 0xFF);
    return out;
}

}

static const size_t HASH_LEN = 64;

class BigInt {
public:
    vector<u32> d;

    BigInt() { d.push_back(0); }
    BigInt(u64 v) {
        d.push_back((u32)(v & 0xFFFFFFFFu));
        d.push_back((u32)((v >> 32) & 0xFFFFFFFFu));
        trim();
    }

    void trim() { while (d.size() > 1 && d.back() == 0) d.pop_back(); }

    bool isZero() const { return d.size() == 1 && d[0] == 0; }
    bool isEven() const { return (d[0] & 1) == 0; }

    size_t bitLength() const {
        if (isZero()) return 0;
        size_t bits = (d.size() - 1) * 32;
        u32 top = d.back();
        while (top) { bits++; top >>= 1; }
        return bits;
    }

    int cmp(const BigInt& o) const {
        if (d.size() != o.d.size()) return d.size() < o.d.size() ? -1 : 1;
        for (int i = (int)d.size() - 1; i >= 0; --i)
            if (d[i] != o.d[i]) return d[i] < o.d[i] ? -1 : 1;
        return 0;
    }
    bool operator==(const BigInt& o) const { return cmp(o) == 0; }
    bool operator!=(const BigInt& o) const { return cmp(o) != 0; }
    bool operator<(const BigInt& o)  const { return cmp(o) < 0; }
    bool operator>(const BigInt& o)  const { return cmp(o) > 0; }
    bool operator<=(const BigInt& o) const { return cmp(o) <= 0; }
    bool operator>=(const BigInt& o) const { return cmp(o) >= 0; }

    BigInt operator+(const BigInt& o) const {
        BigInt r; r.d.clear();
        u64 carry = 0;
        size_t n = std::max(d.size(), o.d.size());
        for (size_t i = 0; i < n || carry; ++i) {
            u64 s = carry;
            if (i < d.size())   s += d[i];
            if (i < o.d.size()) s += o.d[i];
            r.d.push_back((u32)(s & 0xFFFFFFFFu));
            carry = s >> 32;
        }
        r.trim();
        return r;
    }

    BigInt operator-(const BigInt& o) const {
        BigInt r; r.d.clear();
        i64 borrow = 0;
        for (size_t i = 0; i < d.size(); ++i) {
            i64 diff = (i64)d[i] - borrow - (i < o.d.size() ? (i64)o.d[i] : 0);
            if (diff < 0) { diff += 0x100000000LL; borrow = 1; } else borrow = 0;
            r.d.push_back((u32)diff);
        }
        r.trim();
        return r;
    }

    BigInt operator*(const BigInt& o) const {
        BigInt r; r.d.assign(d.size() + o.d.size(), 0);
        for (size_t i = 0; i < d.size(); ++i) {
            u64 carry = 0;
            for (size_t j = 0; j < o.d.size() || carry; ++j) {
                u64 cur = r.d[i + j] + carry;
                if (j < o.d.size()) cur += (u64)d[i] * o.d[j];
                r.d[i + j] = (u32)(cur & 0xFFFFFFFFu);
                carry = cur >> 32;
            }
        }
        r.trim();
        return r;
    }

    BigInt shl(size_t bits) const {
        if (isZero() || bits == 0) return *this;
        size_t limbShift = bits / 32, bitShift = bits % 32;
        BigInt r; r.d.assign(d.size() + limbShift + 1, 0);
        for (size_t i = 0; i < d.size(); ++i) {
            u64 v = (u64)d[i] << bitShift;
            r.d[i + limbShift]     |= (u32)(v & 0xFFFFFFFFu);
            r.d[i + limbShift + 1] |= (u32)(v >> 32);
        }
        r.trim();
        return r;
    }

    BigInt shr1() const {
        BigInt r; r.d.assign(d.size(), 0);
        u32 carry = 0;
        for (int i = (int)d.size() - 1; i >= 0; --i) {
            r.d[i] = (d[i] >> 1) | (carry << 31);
            carry = d[i] & 1;
        }
        r.trim();
        return r;
    }

    bool getBit(size_t i) const {
        size_t limb = i / 32, bit = i % 32;
        if (limb >= d.size()) return false;
        return (d[limb] >> bit) & 1;
    }

    void divmod(const BigInt& divisor, BigInt& q, BigInt& r) const {
        if (divisor.isZero()) throw std::runtime_error("div by zero");
        size_t bits = bitLength();
        if (bits == 0) { q = BigInt(0); r = BigInt(0); return; }

        r.d.assign(d.size() + 1, 0);
        r.trim();

        q.d.assign((bits + 31) / 32, 0);

        auto r_shl1_inplace = [&]() {
            u32 carry = 0;
            for (size_t i = 0; i < r.d.size(); ++i) {
                u32 newCarry = r.d[i] >> 31;
                r.d[i] = (r.d[i] << 1) | carry;
                carry = newCarry;
            }
            if (carry) r.d.push_back(carry);
        };
        auto r_ge_divisor = [&]() -> bool {
            if (r.d.size() != divisor.d.size()) {
                if (r.d.size() < divisor.d.size()) return false;
                for (size_t i = divisor.d.size(); i < r.d.size(); ++i)
                    if (r.d[i] != 0) return true;
                for (int i = (int)divisor.d.size() - 1; i >= 0; --i)
                    if (r.d[i] != divisor.d[i]) return r.d[i] > divisor.d[i];
                return true;
            }
            for (int i = (int)divisor.d.size() - 1; i >= 0; --i)
                if (r.d[i] != divisor.d[i]) return r.d[i] > divisor.d[i];
            return true;
        };
        auto r_sub_divisor_inplace = [&]() {
            i64 borrow = 0;
            for (size_t i = 0; i < divisor.d.size() || borrow; ++i) {
                i64 cur = (i64)r.d[i] - borrow - (i < divisor.d.size() ? (i64)divisor.d[i] : 0);
                if (cur < 0) { cur += 0x100000000LL; borrow = 1; } else borrow = 0;
                r.d[i] = (u32)cur;
            }
            while (r.d.size() > 1 && r.d.back() == 0) r.d.pop_back();
        };

        for (int i = (int)bits - 1; i >= 0; --i) {
            r_shl1_inplace();
            if (getBit(i)) r.d[0] |= 1;
            if (r_ge_divisor()) {
                r_sub_divisor_inplace();
                size_t limb = i / 32, bit = i % 32;
                q.d[limb] |= (1u << bit);
            }
        }
        q.trim();
        r.trim();
    }

    BigInt operator/(const BigInt& o) const { BigInt q, r; divmod(o, q, r); return q; }
    BigInt operator%(const BigInt& o) const { BigInt q, r; divmod(o, q, r); return r; }

    vector<u8> toBytes(size_t len) const {
        vector<u8> out(len, 0);
        for (size_t i = 0; i < len; ++i) {
            size_t limb = i / 4;
            size_t off  = i % 4;
            u8 b = (limb < d.size()) ? (u8)((d[limb] >> (off * 8)) & 0xFF) : 0;
            out[len - 1 - i] = b;
        }
        return out;
    }

    static BigInt fromBytes(const vector<u8>& b) {
        BigInt r(0);
        for (u8 byte : b) {
            r = r.shl(8);
            r.d[0] |= byte;
        }
        return r;
    }

    string toHex() const {
        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0');
        ss << std::setw(8) << d.back();
        for (int i = (int)d.size() - 2; i >= 0; --i)
            ss << std::setw(8) << d[i];
        return ss.str();
    }
};

BigInt modSub(const BigInt& a, const BigInt& b, const BigInt& m) {
    if (a >= b) return a - b;
    return (a + m) - b;
}

BigInt modPow(BigInt base, BigInt exp, const BigInt& mod) {
    BigInt result(1);
    base = base % mod;
    while (!exp.isZero()) {
        if (exp.d[0] & 1) result = (result * base) % mod;
        exp = exp.shr1();
        if (!exp.isZero()) base = (base * base) % mod;
    }
    return result;
}

BigInt modInverse(BigInt a, const BigInt& m) {
    a = a % m;
    BigInt t(0), newt(1);
    BigInt r = m, newr = a;
    while (!newr.isZero()) {
        BigInt q = r / newr;
        BigInt qn = (q * newt) % m;
        BigInt tmp = modSub(t % m, qn, m);
        t = newt; newt = tmp;
        BigInt rr = r - q * newr;
        r = newr; newr = rr;
    }
    if (r > BigInt(1)) throw std::runtime_error("modInverse: not invertible");
    return t % m;
}

static const vector<u32>& smallPrimes() {
    static vector<u32> primes = []{
        const u32 LIM = 10000;
        vector<bool> sieve(LIM + 1, true);
        sieve[0] = sieve[1] = false;
        for (u32 i = 2; i * i <= LIM; ++i)
            if (sieve[i])
                for (u32 j = i * i; j <= LIM; j += i) sieve[j] = false;
        vector<u32> v;
        for (u32 i = 2; i <= LIM; ++i) if (sieve[i]) v.push_back(i);
        return v;
    }();
    return primes;
}

static u32 modSmall(const BigInt& n, u32 m) {
    u64 r = 0;
    for (int i = (int)n.d.size() - 1; i >= 0; --i)
        r = ((r << 32) | n.d[i]) % m;
    return (u32)r;
}

static bool passesSmallPrimes(const BigInt& n) {
    for (u32 p : smallPrimes()) {
        if (p == 2) {
            if (n.isEven() && !(n.d.size() == 1 && n.d[0] == 2)) return false;
            continue;
        }
        if (n.d.size() == 1 && n.d[0] == p) return true;
        if (modSmall(n, p) == 0) return false;
    }
    return true;
}

static std::mt19937_64 g_rng{
    (u64)std::chrono::high_resolution_clock::now().time_since_epoch().count()
};

BigInt randomBigInt(size_t bits) {
    BigInt r(0);
    size_t limbs = (bits + 31) / 32;
    r.d.assign(limbs, 0);
    for (size_t i = 0; i < limbs; ++i) r.d[i] = (u32)g_rng();
    size_t topBits = bits % 32;
    if (topBits) r.d[limbs - 1] &= (1u << topBits) - 1;
    r.d[limbs - 1] |= (1u << ((bits - 1) % 32));
    r.trim();
    return r;
}

bool isPrimeMillerRabin(const BigInt& n, int rounds = 8) {
    if (n < BigInt(2)) return false;
    if (n == BigInt(2) || n == BigInt(3)) return true;
    if (n.isEven()) return false;

    BigInt n1 = n - BigInt(1);
    BigInt dd = n1;
    size_t s = 0;
    while (dd.isEven()) { dd = dd.shr1(); s++; }

    for (int i = 0; i < rounds; ++i) {
        BigInt a;
        do {
            a = randomBigInt(n.bitLength());
            a = a % (n - BigInt(3));
        } while (a < BigInt(2));
        a = a + BigInt(2);

        BigInt x = modPow(a, dd, n);
        if (x == BigInt(1) || x == n1) continue;
        bool witness = true;
        for (size_t r = 1; r < s; ++r) {
            x = (x * x) % n;
            if (x == n1) { witness = false; break; }
        }
        if (witness) return false;
    }
    return true;
}

BigInt generatePrime(size_t bits) {
    size_t attempts = 0;
    while (true) {
        BigInt c = randomBigInt(bits);
        c.d[0] |= 1;
        ++attempts;
        if (!passesSmallPrimes(c)) continue;
        if (isPrimeMillerRabin(c)) {
            cout << "    (попыток до простого: " << attempts << ")" << endl;
            return c;
        }
    }
}

struct RSAPrivateKey {
    BigInt N, e, d, p, q, dp, dq, qinv;
    size_t k;
};

RSAPrivateKey rsaGenerate(size_t bits) {
    RSAPrivateKey key;
    key.k = (bits + 7) / 8;
    size_t half = bits / 2;

    cout << "[*] Генерация p (" << half << " бит)..." << endl;
    key.p = generatePrime(half);
    cout << "[*] Генерация q (" << half << " бит)..." << endl;
    do { key.q = generatePrime(half); } while (key.p == key.q);

    key.N = key.p * key.q;
    key.e = BigInt(65537);

    BigInt phi = (key.p - BigInt(1)) * (key.q - BigInt(1));
    if ((phi % key.e).isZero())
        throw std::runtime_error("e not coprime with phi");

    key.d = modInverse(key.e, phi);

    key.dp   = key.d % (key.p - BigInt(1));
    key.dq   = key.d % (key.q - BigInt(1));
    key.qinv = modInverse(key.q, key.p);

    return key;
}

BigInt rsaEncrypt(const BigInt& m, const BigInt& e, const BigInt& N) {
    return modPow(m, e, N);
}

BigInt rsaDecryptCRT(const BigInt& c, const RSAPrivateKey& key) {
    BigInt m1 = modPow(c % key.p, key.dp, key.p);
    BigInt m2 = modPow(c % key.q, key.dq, key.q);

    BigInt diff = modSub(m1 % key.p, m2 % key.p, key.p);
    BigInt h    = (key.qinv * diff) % key.p;
    BigInt m    = m2 + h * key.q;
    return m;
}

vector<u8> mgf1(const vector<u8>& seed, size_t length) {
    vector<u8> mask;
    mask.reserve(length);
    u32 counter = 0;
    while (mask.size() < length) {
        vector<u8> input = seed;
        input.push_back((u8)((counter >> 24) & 0xFF));
        input.push_back((u8)((counter >> 16) & 0xFF));
        input.push_back((u8)((counter >> 8)  & 0xFF));
        input.push_back((u8)( counter        & 0xFF));
        vector<u8> h = sha512_ns::hash(input);
        mask.insert(mask.end(), h.begin(), h.end());
        counter++;
    }
    mask.resize(length);
    return mask;
}

vector<u8> oaepEncode(const vector<u8>& M, size_t k) {
    if (k < 2 * HASH_LEN + 2)
        throw std::runtime_error("k too small for OAEP(SHA-512)");
    size_t maxLen = k - 2 * HASH_LEN - 2;
    if (M.size() > maxLen)
        throw std::runtime_error("message too long");

    vector<u8> lHash = sha512_ns::hash({});
    size_t psLen = k - M.size() - 2 * HASH_LEN - 2;

    vector<u8> DB;
    DB.reserve(k - HASH_LEN - 1);
    DB.insert(DB.end(), lHash.begin(), lHash.end());
    DB.insert(DB.end(), psLen, 0x00);
    DB.push_back(0x01);
    DB.insert(DB.end(), M.begin(), M.end());

    vector<u8> seed(HASH_LEN);
    for (size_t i = 0; i < HASH_LEN; i += 8) {
        u64 v = g_rng();
        for (int j = 0; j < 8; ++j) seed[i + j] = (u8)((v >> (j*8)) & 0xFF);
    }

    vector<u8> dbMask = mgf1(seed, k - HASH_LEN - 1);
    vector<u8> maskedDB(DB.size());
    for (size_t i = 0; i < DB.size(); ++i) maskedDB[i] = DB[i] ^ dbMask[i];

    vector<u8> seedMask = mgf1(maskedDB, HASH_LEN);
    vector<u8> maskedSeed(HASH_LEN);
    for (size_t i = 0; i < HASH_LEN; ++i) maskedSeed[i] = seed[i] ^ seedMask[i];

    vector<u8> EM;
    EM.reserve(k);
    EM.push_back(0x00);
    EM.insert(EM.end(), maskedSeed.begin(), maskedSeed.end());
    EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());
    return EM;
}

static inline u8 ct_eq_u8(u8 a, u8 b) {
    u8 x = (u8)(a ^ b);
    u8 nz = (u8)(((u32)x | (u32)(-(i32)x)) >> 7);
    return (u8)(nz - 1);
}

vector<u8> oaepDecode(const vector<u8>& EM, size_t k) {
    if (EM.size() != k) throw std::runtime_error("bad EM length");

    vector<u8> maskedSeed(EM.begin() + 1, EM.begin() + 1 + HASH_LEN);
    vector<u8> maskedDB  (EM.begin() + 1 + HASH_LEN, EM.end());

    vector<u8> seedMask = mgf1(maskedDB, HASH_LEN);
    vector<u8> seed(HASH_LEN);
    for (size_t i = 0; i < HASH_LEN; ++i) seed[i] = maskedSeed[i] ^ seedMask[i];

    vector<u8> dbMask = mgf1(seed, k - HASH_LEN - 1);
    vector<u8> DB(maskedDB.size());
    for (size_t i = 0; i < maskedDB.size(); ++i) DB[i] = maskedDB[i] ^ dbMask[i];

    vector<u8> lHash = sha512_ns::hash({});

    u8 bad = 0;
    bad |= (u8)(EM[0] != 0x00);
    for (size_t i = 0; i < HASH_LEN; ++i)
        bad |= (u8)(DB[i] != lHash[i]);

    size_t msgStart = DB.size();
    u8 found = 0;
    for (size_t i = HASH_LEN; i < DB.size(); ++i) {
        u8 isOne    = ct_eq_u8(DB[i], 0x01);
        u8 isOneBit = (u8)(isOne & 0x01);
        u8 takeBit  = (u8)(isOneBit & (u8)(found ^ 1));
        u8 takeMask = (u8)((u8)0 - takeBit);
        size_t oldStart = msgStart;
        size_t newStart = i + 1;
        msgStart = (oldStart & (size_t)~takeMask) |
                   (newStart & (size_t) takeMask);
        found |= isOneBit;
    }
    bad |= (u8)(found ^ 1);

    size_t outLen = 0;
    for (size_t i = 0; i < DB.size(); ++i) {
        size_t diff = i - msgStart;
        u8 ge = (u8)((diff >> (sizeof(size_t) * 8 - 1)) ^ 1);
        outLen += ge;
    }

    vector<u8> M(outLen);
    for (size_t i = 0; i < outLen; ++i) M[i] = DB[msgStart + i];

    if (bad != 0) return {};
    return M;
}

BigInt emToInt(const vector<u8>& EM) { return BigInt::fromBytes(EM); }
vector<u8> intToEm(const BigInt& x, size_t k) { return x.toBytes(k); }

vector<u8> encryptBytes(const vector<u8>& M, const RSAPrivateKey& pub, size_t k) {
    vector<u8> EM = oaepEncode(M, k);
    BigInt m = emToInt(EM);
    BigInt c = rsaEncrypt(m, pub.e, pub.N);
    return intToEm(c, k);
}

vector<u8> decryptBytes(const vector<u8>& C, const RSAPrivateKey& key) {
    if (C.size() != key.k) throw std::runtime_error("ciphertext length mismatch");
    BigInt c = emToInt(C);
    BigInt m = rsaDecryptCRT(c, key);
    vector<u8> EM = intToEm(m, key.k);
    return oaepDecode(EM, key.k);
}

static u64 now_ns() {
    return (u64)std::chrono::high_resolution_clock::now()
        .time_since_epoch().count();
}

int main() {
    cout << "=== RSA-2048 / SHA-512 / OAEP + CT-unpad ===\n\n";

    u64 t0 = now_ns();
    RSAPrivateKey key = rsaGenerate(2048);
    u64 t1 = now_ns();
    cout << "[+] Ключи сгенерированы за "
         << std::fixed << std::setprecision(3)
         << (double)(t1 - t0) / 1e9 << " с\n";
    cout << "    N = " << key.N.toHex() << "\n\n";

    string s = "hello oaep + crt!";
    vector<u8> M(s.begin(), s.end());

    vector<u8> C  = encryptBytes(M, key, key.k);
    vector<u8> M2 = decryptBytes(C, key);

    cout << "[+] Исходное:      \"" << s << "\"\n";
    cout << "[+] Восстановлено: \""
         << string(M2.begin(), M2.end()) << "\"\n";
    cout << "[+] Результат: " << ((M == M2) ? "OK" : "FAIL") << "\n\n";

    size_t maxLen = key.k - 2 * HASH_LEN - 2;
    cout << "[+] k = " << key.k
         << " байт, максимальная длина сообщения = "
         << maxLen << " байт\n";

    {
        vector<u8> empty;
        vector<u8> C0 = encryptBytes(empty, key, key.k);
        vector<u8> M0 = decryptBytes(C0, key);
        cout << "    len=0    : " << ((M0 == empty) ? "OK" : "FAIL")
             << " (получено " << M0.size() << " байт)\n";
    }
    {
        vector<u8> maxMsg(maxLen, 0xAB);
        vector<u8> Cm = encryptBytes(maxMsg, key, key.k);
        vector<u8> Mm = decryptBytes(Cm, key);
        cout << "    len=max  : " << ((Mm == maxMsg) ? "OK" : "FAIL")
             << " (получено " << Mm.size() << " байт)\n";
    }
    {
        vector<u8> tooBig(maxLen + 1, 0x00);
        bool threw = false;
        try { encryptBytes(tooBig, key, key.k); }
        catch (const std::exception&) { threw = true; }
        cout << "    len=max+1: "
             << (threw ? "OK (исключение)" : "FAIL (не бросило)") << "\n\n";
    }

    cout << "[+] Constant-time: сравнение времени (100 прогонов)\n";

    auto measure = [&](const vector<u8>& C) {
        for (int i = 0; i < 3; ++i) (void)decryptBytes(C, key);
        u64 t = now_ns();
        for (int i = 0; i < 100; ++i) (void)decryptBytes(C, key);
        return (double)(now_ns() - t) / 100.0;
    };

    vector<u8> good = encryptBytes(M, key, key.k);
    vector<u8> bad  = good;
    bad[HASH_LEN / 2] ^= 0xFF;

    double tGood = measure(good);
    double tBad  = measure(bad);
    cout << std::fixed << std::setprecision(0);
    cout << "    valid   : " << tGood << " ns/op\n";
    cout << "    tampered: " << tBad  << " ns/op\n";
    double rel = (tBad - tGood) / tGood * 100.0;
    cout << std::setprecision(2);
    cout << "    разница : " << rel << "%\n\n";

    cout << "[+] Готово.\n";
    return 0;
}