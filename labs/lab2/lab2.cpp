#include <boost/multiprecision/cpp_int.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <random>
#include <iostream>
#include <algorithm>

using namespace std;

using boost::multiprecision::cpp_int;
using boost::multiprecision::cpp_int_backend;
using boost::multiprecision::unsigned_magnitude;
using boost::multiprecision::unchecked;

using uint2048_t = boost::multiprecision::number<cpp_int_backend<2048, 2048, unsigned_magnitude, unchecked, void>>;
using uint4096_t = boost::multiprecision::number<cpp_int_backend<4096, 4096, unsigned_magnitude, unchecked, void>>;


namespace sha256 {

struct Ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t ch (uint32_t x,uint32_t y,uint32_t z){ return (x & y) ^ (~x & z); }
inline uint32_t maj(uint32_t x,uint32_t y,uint32_t z){ return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t bsig0(uint32_t x){ return rotr(x, 2) ^ rotr(x,13) ^ rotr(x,22); }
inline uint32_t bsig1(uint32_t x){ return rotr(x, 6) ^ rotr(x,11) ^ rotr(x,25); }
inline uint32_t ssig0(uint32_t x){ return rotr(x, 7) ^ rotr(x,18) ^ (x >> 3); }
inline uint32_t ssig1(uint32_t x){ return rotr(x,17) ^ rotr(x,19) ^ (x >> 10); }

void init(Ctx& c) {
    c.state[0]=0x6a09e667; c.state[1]=0xbb67ae85; c.state[2]=0x3c6ef372; c.state[3]=0xa54ff53a;
    c.state[4]=0x510e527f; c.state[5]=0x9b05688c; c.state[6]=0x1f83d9ab; c.state[7]=0x5be0cd19;
    c.bitlen = 0; c.buflen = 0;
}

void compress(Ctx& c, const uint8_t* p) {
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
        w[i] = (uint32_t(p[i*4]) << 24) | (uint32_t(p[i*4+1]) << 16) | (uint32_t(p[i*4+2]) << 8) | uint32_t(p[i*4+3]);
    for (int i = 16; i < 64; ++i)
        w[i] = ssig1(w[i-2]) + w[i-7] + ssig0(w[i-15]) + w[i-16];

    uint32_t a=c.state[0],b=c.state[1],cc=c.state[2],d=c.state[3];
    uint32_t e=c.state[4],f=c.state[5],g=c.state[6],h=c.state[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + bsig1(e) + ch(e,f,g) + K[i] + w[i];
        uint32_t t2 = bsig0(a) + maj(a,b,cc);
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c.state[0]+=a; c.state[1]+=b; c.state[2]+=cc; c.state[3]+=d;
    c.state[4]+=e; c.state[5]+=f; c.state[6]+=g; c.state[7]+=h;
}

void update(Ctx& c, const uint8_t* data, size_t len) {
    c.bitlen += uint64_t(len) * 8;
    while (len > 0) {
        size_t take = min(size_t(64) - c.buflen, len);
        memcpy(c.buf + c.buflen, data, take);
        c.buflen += take; data += take; len -= take;
        if (c.buflen == 64) { compress(c, c.buf); c.buflen = 0; }
    }
}

void final(Ctx& c, uint8_t out[32]) {
    uint64_t bits = c.bitlen;
    uint8_t pad = 0x80;
    update(c, &pad, 1);
    uint8_t zero = 0x00;
    while (c.buflen != 56) update(c, &zero, 1);
    uint8_t lenbuf[8];
    for (int i = 0; i < 8; ++i) lenbuf[i] = uint8_t(bits >> (56 - 8*i));
    update(c, lenbuf, 8);
    for (int i = 0; i < 8; ++i) {
        out[i*4]   = uint8_t(c.state[i] >> 24);
        out[i*4+1] = uint8_t(c.state[i] >> 16);
        out[i*4+2] = uint8_t(c.state[i] >> 8);
        out[i*4+3] = uint8_t(c.state[i]);
    }
}

void hash(const uint8_t* data, size_t len, uint8_t out[32]) {
    Ctx c;
    init(c);
    update(c, data, len);
    final(c, out);
}

}

class BigIntMath {
public:
    static cpp_int egcd(const cpp_int& a, const cpp_int& b, cpp_int& x, cpp_int& y) {
        if (b == 0) { x = 1; y = 0; return a; }
        cpp_int x1, y1;
        cpp_int g = egcd(b, a % b, x1, y1);
        x = y1;
        y = x1 - (a / b) * y1;
        return g;
    }

    static cpp_int gcd(const cpp_int& a, const cpp_int& b) {
        cpp_int x, y;
        return egcd(a, b, x, y);
    }

    static cpp_int lcm(const cpp_int& a, const cpp_int& b) {
        return a / gcd(a, b) * b;
    }

    static cpp_int modinv(const cpp_int& a, const cpp_int& m) {
        cpp_int x, y;
        cpp_int g = egcd(a, m, x, y);
        if (g != 1) return 0;
        x %= m;
        if (x < 0) x += m;
        return x;
    }

    static uint2048_t modpow_ct(uint2048_t base, const cpp_int& exp, const uint2048_t& mod, size_t expBits) {
        uint2048_t r0 = 1;
        uint2048_t r1 = base % mod;

        for (size_t i = 0; i < expBits; ++i) {
            bool bit = boost::multiprecision::bit_test(exp, expBits - 1 - i);

            uint2048_t r0_mul_r1 = (uint4096_t(r0) * r1 % mod).convert_to<uint2048_t>();
            uint2048_t r0_sq = (uint4096_t(r0) * r0 % mod).convert_to<uint2048_t>();
            uint2048_t r1_sq = (uint4096_t(r1) * r1 % mod).convert_to<uint2048_t>();

            uint2048_t m = bit ? ~uint2048_t(0) : uint2048_t(0);

            uint2048_t r0_new = (r0_sq & ~m) | (r0_mul_r1 & m);
            uint2048_t r1_new = (r0_mul_r1 & ~m) | (r1_sq & m);

            r0 = r0_new;
            r1 = r1_new;
        }
        return r0;
    }

    static bool miller_rabin(const cpp_int& n, int rounds) {
        if (n < 2) return false;
        if (n % 2 == 0) return n == 2;

        cpp_int d = n - 1;
        int s = 0;
        while ((d & 1) == 0) { d >>= 1; ++s; }

        const uint32_t bases[] = {2,3,5,7,11,13,17,19,23,29,31,37};
        for (int i = 0; i < rounds && i < 12; ++i) {
            cpp_int a = bases[i] % n;
            if (a == 0) continue;
            cpp_int x = boost::multiprecision::powm(a, d, n);
            if (x == 1 || x == n - 1) continue;
            bool composite = true;
            for (int r = 1; r < s; ++r) {
                x = (x * x) % n;
                if (x == n - 1) { composite = false; break; }
            }
            if (composite) return false;
        }
        return true;
    }

    static cpp_int gen_prime(int bits, mt19937_64& rng) {
        while (true) {
            cpp_int p = 0;
            boost::multiprecision::bit_set(p, bits - 1);
            boost::multiprecision::bit_set(p, 0);
            for (int i = 1; i < bits - 1; ++i)
                if (rng() & 1) boost::multiprecision::bit_set(p, i);
            if (miller_rabin(p, 16)) return p;
        }
    }
};


struct PublicKey {
    uint2048_t N;
    cpp_int e;
};

struct PrivateKey {
    uint2048_t N;
    cpp_int d;
    cpp_int p, q;
    cpp_int dP, dQ, qInv;
    size_t dBits;
};

class RsaCore {
public:
    static void keygen(PublicKey& pub, PrivateKey& priv, int bits = 2048) {
        mt19937_64 rng(random_device{}());
        cpp_int e = 65537;

        while (true) {
            cpp_int p = BigIntMath::gen_prime(bits / 2, rng);
            cpp_int q = BigIntMath::gen_prime(bits / 2, rng);
            if (p == q) continue;

            cpp_int N = p * q;
            cpp_int lambda = BigIntMath::lcm(p - 1, q - 1);

            cpp_int x, y;
            if (BigIntMath::egcd(e, lambda, x, y) != 1) continue;

            cpp_int d = BigIntMath::modinv(e, lambda);
            if (d == 0) continue;

            cpp_int dP = d % (p - 1);
            cpp_int dQ = d % (q - 1);
            cpp_int qInv = BigIntMath::modinv(q % p, p);
            if (qInv == 0) continue;

            pub.N = N.convert_to<uint2048_t>();
            pub.e = e;
            priv.N = pub.N;
            priv.d = d;
            priv.p = p;
            priv.q = q;
            priv.dP = dP;
            priv.dQ = dQ;
            priv.qInv = qInv;
            priv.dBits = boost::multiprecision::msb(d) + 1;
            return;
        }
    }

    static uint2048_t encrypt(const PublicKey& pub, uint2048_t m) {
        return BigIntMath::modpow_ct(m, pub.e, pub.N, boost::multiprecision::msb(pub.e) + 1);
    }

    static uint2048_t decrypt_crt(const PrivateKey& priv, uint2048_t c) {
        cpp_int cp = c.convert_to<cpp_int>() % priv.p;
        cpp_int cq = c.convert_to<cpp_int>() % priv.q;

        cpp_int m1 = boost::multiprecision::powm(cp, priv.dP, priv.p);
        cpp_int m2 = boost::multiprecision::powm(cq, priv.dQ, priv.q);

        cpp_int t = (m1 + priv.p - (m2 % priv.p)) % priv.p;

        cpp_int h = (priv.qInv * t) % priv.p;
        cpp_int m = m2 + h * priv.q;

        return m.convert_to<uint2048_t>();
    }
};

class Oaep {
public:
    static constexpr size_t k = 256;
    static constexpr size_t hLen = 32;
    static constexpr size_t maxMsgLen = k - 2 * hLen - 2;

    static void mgf1(const uint8_t* seed, size_t seedLen, uint8_t* out, size_t outLen) {
        uint32_t counter = 0;
        size_t produced = 0;
        array<uint8_t, k + 4> tmp{};
        while (produced < outLen) {
            tmp.fill(0);
            uint8_t buf[4] = {
                uint8_t(counter >> 24), uint8_t(counter >> 16),
                uint8_t(counter >> 8),  uint8_t(counter)
            };
            memcpy(tmp.data(), seed, seedLen);
            memcpy(tmp.data() + seedLen, buf, 4);

            uint8_t h[32];
            sha256::hash(tmp.data(), seedLen + 4, h);

            size_t take = (outLen - produced < 32) ? (outLen - produced) : 32;
            memcpy(out + produced, h, take);
            produced += take;
            ++counter;
        }
    }

    static void lhash(uint8_t out[32]) {
        sha256::hash(nullptr, 0, out);
    }

    static void encode(const uint8_t* M, size_t mLen, const uint8_t* seed, uint8_t* EM) {
        uint8_t lh[32];
        lhash(lh);

        array<uint8_t, k> DB{};
        memcpy(DB.data(), lh, hLen);

        size_t dbLen = k - hLen - 1;
        size_t psLen = dbLen - hLen - 1 - mLen;
        DB[hLen + psLen] = 0x01;
        if (mLen > 0) {
            memcpy(DB.data() + hLen + psLen + 1, M, mLen);
        }
        array<uint8_t, k> dbMask{};
        mgf1(seed, hLen, dbMask.data(), dbLen);

        array<uint8_t, k> maskedDB{};
        for (size_t i = 0; i < dbLen; ++i) {
            maskedDB[i] = DB[i] ^ dbMask[i];
        }
        uint8_t seedMask[32];
        mgf1(maskedDB.data(), dbLen, seedMask, hLen);

        uint8_t maskedSeed[32];
        for (size_t i = 0; i < hLen; ++i)
            maskedSeed[i] = seed[i] ^ seedMask[i];

        EM[0] = 0x00;
        memcpy(EM + 1, maskedSeed, hLen);
        memcpy(EM + 1 + hLen, maskedDB.data(), dbLen);
    }

    static bool decode_ct(const uint8_t* EM, size_t EM_len, const uint8_t* lh, uint8_t* M, size_t maxMLen, size_t* mLen_out) {
        if (EM_len != k) { *mLen_out = 0; return false; }

        const uint8_t* maskedSeed = EM + 1;
        const uint8_t* maskedDB = EM + 1 + hLen;
        const size_t dbLen = k - hLen - 1;

        uint8_t seedMask[32];
        mgf1(maskedDB, dbLen, seedMask, hLen);
        uint8_t seed[32];
        for (size_t i = 0; i < hLen; ++i) {
            seed[i] = maskedSeed[i] ^ seedMask[i];
        }

        array<uint8_t, k> dbMask{};
        mgf1(seed, hLen, dbMask.data(), dbLen);
        array<uint8_t, k> DB{};
        for (size_t i = 0; i < dbLen; ++i) {
            DB[i] = maskedDB[i] ^ dbMask[i];
        }

        uint8_t err = 0;
        err |= EM[0];
        for (size_t i = 0; i < hLen; ++i) {
            err |= (uint8_t)(DB[i] ^ lh[i]);
        }

        uint32_t sepIdx = (uint32_t)dbLen;
        uint8_t  found  = 0;
        for (size_t i = hLen; i < dbLen; ++i) {
            uint8_t b      = DB[i];
            uint8_t isOne  = ct_is_one_u8(b);
            uint8_t isZero = ct_is_zero_u8(b);

            uint8_t take = (uint8_t)(isOne & (uint8_t)(found ^ 1u));
            uint8_t viol = (uint8_t)((uint8_t)(found ^ 1u) & (uint8_t)(isZero ^ 1u) & (uint8_t)(isOne  ^ 1u));
            err |= viol;

            uint32_t m = ct_mask_u32(take);
            sepIdx = (sepIdx & ~m) | ((uint32_t)i & m);

            found |= isOne;
        }
        err |= (uint8_t)(found ^ 1u);

        uint32_t foundMask = ct_mask_u32(found);
        uint32_t mStart32  = ((uint32_t)dbLen & ~foundMask) | (((uint32_t)sepIdx + 1u) & foundMask);

        size_t mStart = (size_t)mStart32;
        size_t mLen = (mStart < dbLen) ? (dbLen - mStart) : 0;

        uint64_t a = (uint64_t)mLen;
        uint64_t b = (uint64_t)maxMLen;

        uint64_t borrow = (a - b) >> 63;
        uint8_t gt = (uint8_t)(borrow ^ 1u);
        uint64_t neq64  = a ^ b;
        uint8_t neq = (uint8_t)((neq64 | (uint64_t)(0u - neq64)) >> 63);
        uint8_t isGt = (uint8_t)(gt & neq);

        err |= isGt;

        uint64_t maskGt = (uint64_t)0 - (uint64_t)isGt;
        uint64_t mLenMasked = (a & ~maskGt) | (b & maskGt);
        mLen = (size_t)mLenMasked;

        uint8_t errMask = ct_mask_u8(err);

        for (size_t i = 0; i < maxMLen; ++i) {
            size_t idx = mStart + i;

            uint64_t diff_i  = (uint64_t)i  - (uint64_t)mLen;
            uint8_t iLtLen = (uint8_t)((diff_i >> 63) & 1u);

            uint64_t diff_idx = (uint64_t)idx - (uint64_t)dbLen;
            uint8_t idxInDb = (uint8_t)((diff_idx >> 63) & 1u);

            size_t maskIdx = (size_t)0 - (size_t)idxInDb;
            size_t safeIdx = idx & maskIdx;

            uint8_t val = DB[safeIdx];

            uint8_t ok = (uint8_t)(iLtLen & (uint8_t)(errMask ^ 0xFFu));
            uint8_t mask = (uint8_t)(0u - (uint8_t)(ok & 1u));

            M[i] = (uint8_t)(val & mask);
        }
        size_t keep = (size_t)0 - (size_t)((errMask & 1u) ^ 1u);
        *mLen_out = mLen & keep;

        return (errMask & 1u) == 0;
    }

    static void encrypt(const PublicKey& pub, const uint8_t* M, size_t mLen, uint8_t* C, mt19937_64& rng) {
        uint8_t seed[32];
        for (size_t i = 0; i < 32; i += 8) {
            uint64_t v = rng();
            memcpy(seed + i, &v, 8);
        }

        uint8_t EM[k];
        encode(M, mLen, seed, EM);

        uint2048_t m = os2ip(EM, k);
        uint2048_t c = RsaCore::encrypt(pub, m);
        i2osp(c, C, k);
    }

    static bool decrypt(const PrivateKey& priv, const uint8_t* C, size_t CLen, uint8_t* M, size_t maxMLen, size_t* mLen_out) {
        if (CLen != k) { *mLen_out = 0; return false; }
        uint2048_t c = os2ip(C, k);
        uint2048_t m = RsaCore::decrypt_crt(priv, c);

        uint8_t EM[k];
        i2osp(m, EM, k);

        uint8_t lh[32];
        lhash(lh);

        memset(M, 0, maxMLen);
        return decode_ct(EM, k, lh, M, maxMLen, mLen_out);
    }

private:
    static void i2osp(uint2048_t x, uint8_t* out, size_t outLen) {
        memset(out, 0, outLen);
        for (size_t i = 0; i < outLen; ++i) {
            out[outLen - 1 - i] = uint8_t(x & 0xFF);
            x >>= 8;
        }
    }

    static uint2048_t os2ip(const uint8_t* in, size_t inLen) {
        uint2048_t r = 0;
        for (size_t i = 0; i < inLen; ++i) {
            r <<= 8;
            r |= in[i];
        }
        return r;
    }

    static uint8_t ct_is_zero_u8(uint8_t x) {
        uint8_t nz = (uint8_t)((x | (uint8_t)(0u - x)) >> 7);
        return (uint8_t)(nz ^ 1u);
    }
    static uint8_t ct_is_one_u8(uint8_t x) {
        return ct_is_zero_u8((uint8_t)(x ^ 1u));
    }

    static uint8_t ct_lt_u32(uint32_t a, uint32_t b) {
        uint64_t diff = (uint64_t)a - (uint64_t)b;
        return (uint8_t)((diff >> 63) & 1u);
    }

    static uint32_t ct_mask_u32(uint8_t cond) {
        return (uint32_t)0 - (uint32_t)(cond & 1u);
    }
    static uint8_t ct_mask_u8(uint8_t cond) {
        return (uint8_t)(0u - (uint8_t)(cond & 1u));
    }
};


static uint64_t rdtsc() {
    unsigned lo, hi;
    __asm__ __volatile__("lfence; rdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    return (uint64_t(hi) << 32) | lo;
}


int main() {
    cout << "RSA-2048 + CRT + OAEP\n";

    cout << "[*] Генерация ключей (2048 бит)...\n";
    PublicKey pub;
    PrivateKey priv;
    RsaCore::keygen(pub, priv, 2048);
    cout << "e = " << pub.e << "\n";
    cout << "d (бит) = " << priv.dBits << "\n";

    mt19937_64 rng(random_device{}());

    const char* msg1 = "Hello, RSA-OAEP constant-time!";
    size_t mLen1 = strlen(msg1);
    uint8_t C1[Oaep::k];
    Oaep::encrypt(pub, (const uint8_t*)msg1, mLen1, C1, rng);

    uint8_t M1[Oaep::maxMsgLen];
    size_t  outLen1 = 0;
    bool ok1 = Oaep::decrypt(priv, C1, Oaep::k, M1, sizeof(M1), &outLen1);
    cout << "[T1] round-trip: " << (ok1 ? "OK" : "FAIL") << ", длина=" << outLen1 << ", сообщение=\"" << string((char*)M1, outLen1) << "\"\n";

    uint8_t C2[Oaep::k];
    Oaep::encrypt(pub, nullptr, 0, C2, rng);
    uint8_t M2[Oaep::maxMsgLen];
    size_t outLen2 = 0;
    bool ok2 = Oaep::decrypt(priv, C2, Oaep::k, M2, sizeof(M2), &outLen2);
    cout << "[T2] пустое сообщение: " << (ok2 ? "OK" : "FAIL") << ", длина=" << outLen2 << "\n";

    vector<uint8_t> big(Oaep::maxMsgLen);
    for (size_t i = 0; i < big.size(); ++i) big[i] = uint8_t(i & 0xFF);
    uint8_t C3[Oaep::k];
    Oaep::encrypt(pub, big.data(), big.size(), C3, rng);
    uint8_t M3[Oaep::maxMsgLen];
    size_t outLen3 = 0;
    bool ok3 = Oaep::decrypt(priv, C3, Oaep::k, M3, sizeof(M3), &outLen3);
    bool eq3 = ok3 && (outLen3 == big.size()) && (memcmp(M3, big.data(), outLen3) == 0);
    cout << "[T3] максимальная длина: " << (eq3 ? "OK" : "FAIL") << ", длина=" << outLen3 << "/" << big.size() << "\n";

    const char* msg4 = "tamper test";
    uint8_t C4[Oaep::k];
    Oaep::encrypt(pub, (const uint8_t*)msg4, strlen(msg4), C4, rng);
    C4[10] ^= 0x01;
    uint8_t M4[Oaep::maxMsgLen];
    size_t outLen4 = 123;
    bool ok4 = Oaep::decrypt(priv, C4, Oaep::k, M4, sizeof(M4), &outLen4);
    cout << "[T4] поврежденный шифротекст: " << (ok4 ? " неожиданно OK" : "OK (отклонен)") << ", длина=" << outLen4 << "\n";
    bool all_zero = true;
    for (size_t i = 0; i < Oaep::maxMsgLen; ++i)
        if (M4[i] != 0) { all_zero = false; break; }
    cout << " буфер M обнулен: " << (all_zero ? "да" : "нет") << "\n";

    const int N = 300;
    uint8_t M5[Oaep::maxMsgLen];
    size_t outLen5;

    vector<array<uint8_t, Oaep::k>> bads;
    for (int pos : {0, 1, 33, 100, 200, 255}) {
        const char* msg = "timing";
        array<uint8_t, Oaep::k> C{};
        Oaep::encrypt(pub, (const uint8_t*)msg, strlen(msg), C.data(), rng);
        C[pos] ^= 0xFF;
        bads.push_back(C);
    }

    vector<array<uint8_t, Oaep::k>> goods;
    for (size_t len : {size_t(0), size_t(16), size_t(64), Oaep::maxMsgLen}) {
        vector<uint8_t> m(len, 0xAB);
        array<uint8_t, Oaep::k> C{};
        Oaep::encrypt(pub, m.data(), m.size(), C.data(), rng);
        goods.push_back(C);
    }

    for (int i = 0; i < 5; ++i) {
        Oaep::decrypt(priv, goods[0].data(), Oaep::k, M5, sizeof(M5), &outLen5);
        Oaep::decrypt(priv, bads[0].data(), Oaep::k, M5, sizeof(M5), &outLen5);
    }

    uint64_t tValid = 0, tBad = 0;
    for (int i = 0; i < N; ++i) {
        const auto& C = goods[i % goods.size()];
        uint64_t t0 = rdtsc();
        Oaep::decrypt(priv, C.data(), Oaep::k, M5, sizeof(M5), &outLen5);
        uint64_t t1 = rdtsc();
        tValid += (t1 - t0);
    }
    for (int i = 0; i < N; ++i) {
        const auto& C = bads[i % bads.size()];
        uint64_t t0 = rdtsc();
        Oaep::decrypt(priv, C.data(), Oaep::k, M5, sizeof(M5), &outLen5);
        uint64_t t1 = rdtsc();
        tBad += (t1 - t0);
    }
    cout << "[T5] средние такты: валидный=" << (tValid / N) << ", поврежденный=" << (tBad / N) << ", разница=" << (int64_t(tValid / N) - int64_t(tBad / N)) << "\n";
    cout << "Готово\n";
    return 0;
}