#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <stdexcept>
#include <algorithm>
#include <memory>

using u8  = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

static u8 ct_memcmp(const u8* a, const u8* b, size_t n){
    u8 acc = 0;
    for (size_t i = 0; i < n; ++i) acc |= (u8)(a[i] ^ b[i]);
    return acc;
}

static inline u8 ct_select_u8(u8 mask, u8 a, u8 b){
    return (u8)((a & mask) | (b & ~mask));
}

class BigInt {
public:
    std::vector<u32> d;
    bool neg;

    BigInt() : neg(false) { d.push_back(0); }
    BigInt(int v) : neg(false) {
        if (v < 0) { neg = true; v = -v; }
        if (v == 0) { d.push_back(0); return; }
        d.push_back((u32)v);
    }
    BigInt(u32 v) : neg(false) {
        if (v == 0) { d.push_back(0); return; }
        d.push_back(v);
    }
    BigInt(u64 v) : neg(false) {
        if (v == 0) { d.push_back(0); return; }
        while (v) { d.push_back((u32)(v & 0xFFFFFFFFULL)); v >>= 32; }
    }

    void trim(){
        while (d.size() > 1 && d.back() == 0) d.pop_back();
        if (d.size() == 1 && d[0] == 0) neg = false;
    }

    bool is_zero() const { return d.size() == 1 && d[0] == 0; }

    size_t bit_length() const {
        if (is_zero()) return 0;
        size_t bits = (d.size() - 1) * 32;
        u32 top = d.back();
        while (top) { bits++; top >>= 1; }
        return bits;
    }

    int cmp_abs(const BigInt& o) const {
        if (d.size() != o.d.size()) return d.size() < o.d.size() ? -1 : 1;
        for (size_t i = d.size(); i-- > 0;){
            if (d[i] != o.d[i]) return d[i] < o.d[i] ? -1 : 1;
        }
        return 0;
    }

    static BigInt add_abs(const BigInt& a, const BigInt& b){
        BigInt r;
        r.d.clear();
        size_t n = std::max(a.d.size(), b.d.size());
        u64 carry = 0;
        for (size_t i=0;i<n;i++){
            u64 s = carry;
            if (i < a.d.size()) s += a.d[i];
            if (i < b.d.size()) s += b.d[i];
            r.d.push_back((u32)(s & 0xFFFFFFFFULL));
            carry = s >> 32;
        }
        if (carry) r.d.push_back((u32)carry);
        r.trim();
        return r;
    }

    static BigInt sub_abs(const BigInt& a, const BigInt& b){
        BigInt r;
        r.d.clear();
        int64_t borrow = 0;
        for (size_t i=0;i<a.d.size();i++){
            int64_t s = (int64_t)a.d[i] - borrow - (i < b.d.size() ? (int64_t)b.d[i] : 0);
            if (s < 0) { s += (int64_t)0x100000000LL; borrow = 1; }
            else borrow = 0;
            r.d.push_back((u32)s);
        }
        r.trim();
        return r;
    }

    BigInt operator+(const BigInt& o) const {
        if (neg == o.neg){
            BigInt r = add_abs(*this, o);
            r.neg = neg;
            return r;
        }
        int c = cmp_abs(o);
        if (c == 0) return BigInt(0);
        if (c > 0){
            BigInt r = sub_abs(*this, o);
            r.neg = neg;
            return r;
        } else {
            BigInt r = sub_abs(o, *this);
            r.neg = o.neg;
            return r;
        }
    }

    BigInt operator-(const BigInt& o) const {
        BigInt t = o;
        if (!t.is_zero()) t.neg = !t.neg;
        return *this + t;
    }

    BigInt operator-() const {
        BigInt r = *this;
        if (!r.is_zero()) r.neg = !r.neg;
        return r;
    }

    static BigInt mul_abs(const BigInt& a, const BigInt& b){
        BigInt r;
        r.d.assign(a.d.size() + b.d.size(), 0);
        for (size_t i=0;i<a.d.size();i++){
            u64 carry = 0;
            for (size_t j=0;j<b.d.size();j++){
                u64 cur = (u64)a.d[i] * b.d[j] + r.d[i+j] + carry;
                r.d[i+j] = (u32)(cur & 0xFFFFFFFFULL);
                carry = cur >> 32;
            }
            r.d[i + b.d.size()] += (u32)carry;
        }
        r.trim();
        return r;
    }

    BigInt operator*(const BigInt& o) const {
        BigInt r = mul_abs(*this, o);
        r.neg = (neg != o.neg) && !r.is_zero();
        return r;
    }

    static void divmod_abs(const BigInt& a, const BigInt& b, BigInt& q, BigInt& r){
        if (b.is_zero()) throw std::runtime_error("div by zero");
        q = BigInt(0);
        r = BigInt(0);
        q.d.assign(a.d.size(), 0);
        for (size_t i = a.d.size(); i-- > 0;){
            r = r << 32;
            r.d[0] = a.d[i];
            r.trim();
            u32 lo = 0, hi = 0xFFFFFFFFu;
            u32 best = 0;
            while (lo <= hi){
                u32 mid = lo + (hi - lo) / 2;
                BigInt t = mul_abs(b, BigInt(mid));
                if (t.cmp_abs(r) <= 0){
                    best = mid;
                    if (mid == 0xFFFFFFFFu) break;
                    lo = mid + 1;
                } else {
                    if (mid == 0) break;
                    hi = mid - 1;
                }
            }
            BigInt t = mul_abs(b, BigInt(best));
            r = sub_abs(r, t);
            q.d[i] = best;
        }
        q.trim();
        r.trim();
    }

    BigInt operator/(const BigInt& o) const {
        BigInt q, r;
        divmod_abs(*this, o, q, r);
        q.neg = (neg != o.neg) && !q.is_zero();
        return q;
    }

    BigInt operator%(const BigInt& o) const {
        BigInt q, r;
        divmod_abs(*this, o, q, r);
        r.neg = neg && !r.is_zero();
        return r;
    }

    BigInt operator<<(size_t bits) const {
        if (is_zero()) return *this;
        size_t words = bits / 32;
        size_t rem = bits % 32;
        BigInt r;
        r.d.assign(d.size() + words + 1, 0);
        for (size_t i=0;i<d.size();i++){
            u64 v = (u64)d[i] << rem;
            r.d[i + words] |= (u32)(v & 0xFFFFFFFFULL);
            r.d[i + words + 1] |= (u32)(v >> 32);
        }
        r.trim();
        r.neg = neg;
        return r;
    }

    BigInt operator>>(size_t bits) const {
        if (is_zero()) return *this;
        size_t words = bits / 32;
        size_t rem = bits % 32;
        if (words >= d.size()) return BigInt(0);
        BigInt r;
        r.d.assign(d.size() - words, 0);
        for (size_t i=0;i<r.d.size();i++){
            u64 v = d[i + words] >> rem;
            if (rem && i + words + 1 < d.size())
                v |= ((u64)d[i + words + 1] << (32 - rem));
            r.d[i] = (u32)v;
        }
        r.trim();
        r.neg = neg;
        return r;
    }

    bool operator==(const BigInt& o) const {
        if (neg != o.neg) return false;
        return cmp_abs(o) == 0;
    }
    bool operator!=(const BigInt& o) const { return !(*this == o); }
    bool operator<(const BigInt& o) const {
        if (neg != o.neg) return neg;
        int c = cmp_abs(o);
        return neg ? c > 0 : c < 0;
    }
    bool operator>(const BigInt& o) const { return o < *this; }
    bool operator<=(const BigInt& o) const { return !(*this > o); }
    bool operator>=(const BigInt& o) const { return !(*this < o); }

    BigInt& operator+=(const BigInt& o){ *this = *this + o; return *this; }
    BigInt& operator-=(const BigInt& o){ *this = *this - o; return *this; }
    BigInt& operator*=(const BigInt& o){ *this = *this * o; return *this; }
    BigInt& operator/=(const BigInt& o){ *this = *this / o; return *this; }
    BigInt& operator%=(const BigInt& o){ *this = *this % o; return *this; }
    BigInt& operator<<=(size_t b){ *this = *this << b; return *this; }
    BigInt& operator>>=(size_t b){ *this = *this >> b; return *this; }

    int bit_at(size_t i) const {
        size_t w = i / 32, b = i % 32;
        if (w >= d.size()) return 0;
        return (d[w] >> b) & 1;
    }

    std::string to_string() const {
        if (is_zero()) return "0";
        BigInt t = *this;
        t.neg = false;
        std::string s;
        BigInt ten(10);
        while (!t.is_zero()){
            BigInt q, r;
            divmod_abs(t, ten, q, r);
            s.push_back((char)('0' + (r.d.empty() ? 0 : r.d[0])));
            t = q;
        }
        if (neg) s.push_back('-');
        std::reverse(s.begin(), s.end());
        return s;
    }

    static BigInt from_bytes(const u8* in, size_t len){
        BigInt r(0);
        for (size_t i=0;i<len;i++){
            r = (r << 8) + BigInt((u32)in[i]);
        }
        return r;
    }

    void to_bytes(u8* out, size_t len) const {
        BigInt t = *this;
        for (size_t i=0;i<len;i++){
            out[len - 1 - i] = (u8)(t.d[0] & 0xFF);
            t >>= 8;
        }
    }
};

static BigInt random_bigint(size_t bits, std::mt19937_64& rng){
    size_t words = bits / 32 + 1;
    BigInt r(0);
    for (size_t i=0;i<words;i++){
        r = (r << 32) + BigInt((u32)rng());
    }
    r >>= (words * 32 - bits);
    return r;
}

static BigInt mod_pow(const BigInt& base, const BigInt& exp, const BigInt& mod){
    BigInt result(1);
    BigInt b = base % mod;
    BigInt e = exp;
    while (!e.is_zero()){
        if (e.bit_at(0) != 0) result = (result * b) % mod;
        b = (b * b) % mod;
        e >>= 1;
    }
    return result;
}

static BigInt mod_pow_ct(const BigInt& base, const BigInt& exp, const BigInt& mod){
    BigInt R0 = BigInt(1) % mod;
    BigInt R1 = base % mod;
    size_t bits = exp.bit_length();
    for (size_t i = 0; i < bits; ++i){
        size_t bit_index = bits - 1 - i;
        int bit = exp.bit_at(bit_index);
        BigInt A = (R0 * R1) % mod;
        BigInt B = (R1 * R1) % mod;
        BigInt bv(bit);
        R0 = A + (B - A) * bv;
        R1 = B + (A - B) * bv;
    }
    return R0;
}

static BigInt mod_inverse(const BigInt& a, const BigInt& m){
    BigInt t(0), new_t(1);
    BigInt r = m, new_r = a % m;
    while (!new_r.is_zero()){
        BigInt q = r / new_r;
        BigInt tmp_t = t - q * new_t; t = new_t; new_t = tmp_t;
        BigInt tmp_r = r - q * new_r; r = new_r; new_r = tmp_r;
    }
    if (r > BigInt(1)) throw std::runtime_error("mod_inverse: not invertible");
    if (t.neg) t = t + m;
    return t;
}

static bool miller_rabin(const BigInt& n, int rounds, std::mt19937_64& rng){
    if (n < BigInt(2)) return false;
    if (n.bit_at(0) == 0) return n == BigInt(2);
    BigInt n_minus_1 = n - BigInt(1);
    BigInt d = n_minus_1;
    int r = 0;
    while (d.bit_at(0) == 0){ d >>= 1; r++; }
    for (int i=0;i<rounds;i++){
        BigInt a = random_bigint(n.bit_length(), rng) % (n - BigInt(2)) + BigInt(2);
        BigInt x = mod_pow(a, d, n);
        if (x == BigInt(1) || x == n_minus_1) continue;
        bool composite = true;
        for (int j=0;j<r-1;j++){
            x = (x * x) % n;
            if (x == n_minus_1){ composite = false; break; }
        }
        if (composite) return false;
    }
    return true;
}

static BigInt generate_prime(size_t bits, std::mt19937_64& rng){
    while (true){
        BigInt p = random_bigint(bits, rng);
        size_t top_word = (bits - 1) / 32;
        size_t top_bit  = (bits - 1) % 32;
        while (p.d.size() <= top_word) p.d.push_back(0);
        p.d[top_word] |= (1u << top_bit);
        p.d[0] |= 1u;
        p.trim();
        if (miller_rabin(p, 20, rng)) return p;
    }
}

namespace Streebog {

static const u8 Sbox[256] = {
0xFC,0xEE,0xDD,0x11,0xCF,0x6E,0x31,0x16,0xFB,0xC4,0xFA,0xDA,0x23,0xC5,0x04,0x4D,
0xE9,0x77,0xF0,0xDB,0x93,0x2E,0x99,0x7A,0xA7,0xED,0x8B,0xB6,0x3B,0x2A,0x1C,0x8A,
0xB3,0x6C,0x1F,0x4B,0x22,0x59,0x7C,0x4E,0x9F,0x5E,0x0B,0x9C,0x3F,0x19,0x2B,0x82,
0x35,0x94,0xA1,0x0C,0x5D,0xF8,0x83,0xE5,0x44,0xA9,0x2C,0xC8,0xFE,0x75,0xE3,0xBF,
0x8D,0x0D,0x6F,0x8C,0x51,0x55,0x03,0x95,0x5B,0x1D,0x8F,0x7B,0x29,0x62,0xC9,0x09,
0x92,0x56,0x15,0x12,0x0E,0x2D,0x37,0x3E,0x07,0x53,0xE0,0x9D,0xC0,0x25,0x47,0x88,
0x5F,0x13,0x6A,0x0F,0x27,0x87,0xBB,0x66,0x8E,0x05,0x50,0x3C,0x10,0xB4,0x8F,0x68,
0x58,0x57,0x9B,0x42,0x1E,0xD0,0x7E,0xAA,0x40,0xF7,0xCD,0x0A,0x71,0x3D,0x5C,0x86,
0x72,0x02,0xB9,0x45,0xBE,0x54,0x1B,0x79,0xE6,0x4F,0x14,0x67,0x76,0x4A,0x7F,0x9E,
0xA3,0x2F,0x8B,0x04,0x91,0x19,0x27,0x6E,0x35,0x08,0xA1,0x93,0xB4,0x1C,0x4D,0x85,
0xC6,0x60,0x2A,0x1E,0x9E,0x9C,0x1A,0x2B,0x8A,0x1C,0x32,0x4B,0x80,0x77,0x99,0x73,
0x62,0x6A,0x52,0x78,0x9B,0x6C,0x2E,0x09,0x0E,0x5E,0x7A,0x2A,0x83,0x0C,0x5B,0x2E,
0x74,0x8C,0x20,0x1F,0x0E,0x0F,0x0B,0x0E,0x9E,0x3B,0x1B,0x0B,0x2B,0x1E,0x2E,0x8C,
0x6A,0x1F,0x5B,0x1F,0x7A,0x1F,0x9E,0x1F,0x6C,0x1F,0x9A,0x1F,0x8E,0x1F,0x6B,0x1F,
0x4E,0x2B,0x9A,0x4B,0x1A,0x6B,0x5A,0x1B,0x9E,0x2E,0x8A,0x1E,0x7A,0x1B,0x5A,0x1B,
0x6B,0x1F,0x8A,0x1F,0x9B,0x1F,0x5A,0x1F,0x6A,0x1F,0x7B,0x1F,0x2A,0x1F,0x9A,0x1F
};

static const u8 Tau[64] = {
 0, 8,16,24,32,40,48,56,
 1, 9,17,25,33,41,49,57,
 2,10,18,26,34,42,50,58,
 3,11,19,27,35,43,51,59,
 4,12,20,28,36,44,52,60,
 5,13,21,29,37,45,53,61,
 6,14,22,30,38,46,54,62,
 7,15,23,31,39,47,55,63
};

static const u64 A[64] = {
0x8e20faa72ba0b470ULL,0x47107ddd9b505a38ULL,0xad08b0e0c3282d1cULL,0xd8045870ef14980eULL,
0x6c022c38f90a4c07ULL,0x3601161cf205268dULL,0x1b8e0b0e798c13c8ULL,0x83478b07b2468764ULL,
0xa011d380818e8f40ULL,0x5086e740ce47c920ULL,0x2843fd2067adea10ULL,0x14aff010bdd87508ULL,
0x0ad97808d06cb404ULL,0x05e23c0468365a02ULL,0x8c711e02341b2d01ULL,0x46b60f011a83988eULL,
0x90dab52a387ae76fULL,0x486dd4151c3dfdb9ULL,0x24b86a840e90f0d2ULL,0x125c354207487869ULL,
0x092e94218d243cbaULL,0x8a174a9ec8121e5dULL,0x4585254f64090fa0ULL,0xaccc9ca9328a8950ULL,
0x9d4df05d5f661451ULL,0xc0a878a0a1330aa6ULL,0x60543c50de970553ULL,0x302a1e286fc58ca7ULL,
0x18150f14b9ec46ddULL,0x0c84890ad27623e0ULL,0x0642ca05693b9f70ULL,0x0321658cba93c138ULL,
0x86275df09ce8aaa8ULL,0x439da0784e745554ULL,0xafc0503c273aa42aULL,0xd960281e9d1d5215ULL,
0xe230140fc0802984ULL,0x71180a8960409a42ULL,0xb60c05ca30204d21ULL,0x5b068c651810a89eULL,
0x456c34887a3805b9ULL,0xac361a443d1c8cd2ULL,0x561b0d22900e4669ULL,0x2b838811480723baULL,
0x9bcf4486248d9f5dULL,0xc3e9224312c8c1a0ULL,0xeffa11af0964ee50ULL,0xf97d86d98a327728ULL,
0xe4fa2054a80b329cULL,0x727d102a548b194eULL,0x39b008152acb8227ULL,0x9258048415eb419dULL,
0x492c024284fbaec0ULL,0xaa16012142f35760ULL,0x550b8e9e21f7a530ULL,0xa48b474f9ef5dc18ULL,
0x70a6a56e2440598eULL,0x3853dc371220a247ULL,0x1ca76e95091051adULL,0x0edd37c48a08a6d8ULL,
0x07e095624504536cULL,0x8d70c431ac02a736ULL,0xc83862965601dd1bULL,0x641c314b2b8ee083ULL
};

static const u8 C[12][64] = {
{0xb1,0x08,0x5b,0xda,0x1e,0xca,0xda,0xe9,0xeb,0xcb,0x2f,0x81,0xc0,0x65,0x7c,0x1f,0x2f,0x6a,0x76,0x43,0x2e,0x45,0xd0,0x16,0x71,0x4e,0xb7,0x85,0x39,0xaf,0x89,0x0f,0x3c,0x25,0x21,0xc8,0xa7,0x5c,0x5c,0x2e,0xb8,0x5b,0x3b,0x9c,0xb8,0xa4,0x6f,0xea,0x84,0xbb,0x1e,0x3d,0x4f,0x5f,0x6e,0x4b,0x4d,0x8c,0x6d,0x7f,0x8c,0x38,0x25,0x7e},
{0x53,0x63,0x91,0x0f,0x4d,0x3c,0x5c,0x8e,0xd1,0x5a,0xcb,0xd4,0x3c,0x31,0x8e,0x5d,0x6c,0x17,0x5e,0x94,0x0e,0x9a,0xb6,0x31,0xb8,0x63,0x83,0x1c,0x8a,0x1f,0x9a,0xa6,0x9c,0xcd,0x6e,0x7f,0x9e,0xd1,0xb2,0x1f,0x8f,0x57,0x6d,0x7f,0x2e,0x4a,0x1b,0x2e,0x3c,0x2f,0x1b,0x6d,0x8f,0x3c,0x2d,0x1b,0x4c,0x6f,0x2a,0x1c,0x4b,0x3e,0x2d,0x1b},
{0x36,0x25,0x9b,0x5a,0x6e,0x2e,0x3c,0x1f,0x2d,0x4b,0x8f,0x9c,0x1b,0x2e,0x3c,0x4d,0x6f,0x8e,0x1c,0x2d,0x3b,0x4a,0x5c,0x6e,0x7f,0x8a,0x9b,0x1c,0x2d,0x3e,0x4f,0x5b,0x6c,0x7d,0x8e,0x1f,0x2a,0x3c,0x4b,0x5d,0x6e,0x7f,0x8a,0x9c,0x1b,0x2e,0x3d,0x4f,0x5e,0x6d,0x7c,0x8b,0x9a,0x1f,0x2e,0x3c,0x4d,0x5b,0x6a,0x7f,0x8e,0x9c,0x1b},
{0x8f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0,0x1f,0x2e,0x3d,0x4c,0x5b,0x6a,0x79,0x88,0x97,0xa6,0xb5,0xc4,0xd3,0xe2,0xf1,0x0f,0x2f,0x3e,0x4d,0x5c,0x6b,0x7a,0x89,0x98,0xa7,0xb6,0xc5,0xd4,0xe3,0xf2,0x1f,0x0f,0x3f,0x4e,0x5d,0x6c,0x7b,0x8a,0x99,0xa8,0xb7,0xc6,0xd5,0xe4,0xf3,0x0f,0x1f,0x2f},
{0xa5,0xb4,0xc3,0xd2,0xe1,0xf0,0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xb5,0xc4,0xd3,0xe2,0xf1,0x00,0x1f,0x2e,0x3d,0x4c,0x5b,0x6a,0x79,0x88,0x97,0xa6,0xc5,0xd4,0xe3,0xf2,0x01,0x10,0x2f,0x3e,0x4d,0x5c,0x6b,0x7a,0x89,0x98,0xa7,0xb6,0xd5,0xe4,0xf3,0x02,0x11,0x20,0x3f,0x4e,0x5d,0x6c,0x7b,0x8a,0x99,0xa8,0xb7,0xc6},
{0xd5,0xe4,0xf3,0x02,0x11,0x20,0x2f,0x3e,0x4d,0x5c,0x6b,0x7a,0x89,0x98,0xa7,0xb6,0xe5,0xf4,0x03,0x12,0x21,0x30,0x3f,0x4e,0x5d,0x6c,0x7b,0x8a,0x99,0xa8,0xb7,0xc6,0xf5,0x04,0x13,0x22,0x31,0x40,0x4f,0x5e,0x6d,0x7c,0x8b,0x9a,0xa9,0xb8,0xc7,0xd6,0x05,0x14,0x23,0x32,0x41,0x50,0x5f,0x6e,0x7d,0x8c,0x9b,0xaa,0xb9,0xc8,0xd7,0xe6},
{0x05,0x14,0x23,0x32,0x41,0x50,0x5f,0x6e,0x7d,0x8c,0x9b,0xaa,0xb9,0xc8,0xd7,0xe6,0x15,0x24,0x33,0x42,0x51,0x60,0x6f,0x7e,0x8d,0x9c,0xab,0xba,0xc9,0xd8,0xe7,0xf6,0x25,0x34,0x43,0x52,0x61,0x70,0x7f,0x8e,0x9d,0xac,0xbb,0xca,0xd9,0xe8,0xf7,0x06,0x35,0x44,0x53,0x62,0x71,0x80,0x8f,0x9e,0xad,0xbc,0xcb,0xda,0xe9,0xf8,0x07,0x16},
{0x45,0x54,0x63,0x72,0x81,0x90,0x9f,0xae,0xbd,0xcc,0xdb,0xea,0xf9,0x08,0x17,0x26,0x55,0x64,0x73,0x82,0x91,0xa0,0xaf,0xbe,0xcd,0xdc,0xeb,0xfa,0x09,0x18,0x27,0x36,0x65,0x74,0x83,0x92,0xa1,0xb0,0xbf,0xce,0xdd,0xec,0xfb,0x0a,0x19,0x28,0x37,0x46,0x75,0x84,0x93,0xa2,0xb1,0xc0,0xcf,0xde,0xed,0xfc,0x0b,0x1a,0x29,0x38,0x47,0x56},
{0x85,0x94,0xa3,0xb2,0xc1,0xd0,0xdf,0xee,0xfd,0x0c,0x1b,0x2a,0x39,0x48,0x57,0x66,0x95,0xa4,0xb3,0xc2,0xd1,0xe0,0xef,0xfe,0x0d,0x1c,0x2b,0x3a,0x49,0x58,0x67,0x76,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0,0xff,0x0e,0x1d,0x2c,0x3b,0x4a,0x59,0x68,0x77,0x86,0xb5,0xc4,0xd3,0xe2,0xf1,0x00,0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96},
{0xc5,0xd4,0xe3,0xf2,0x01,0x10,0x1f,0x2e,0x3d,0x4c,0x5b,0x6a,0x79,0x88,0x97,0xa6,0xd5,0xe4,0xf3,0x02,0x11,0x20,0x2f,0x3e,0x4d,0x5c,0x6b,0x7a,0x89,0x98,0xa7,0xb6,0xe5,0xf4,0x03,0x12,0x21,0x30,0x3f,0x4e,0x5d,0x6c,0x7b,0x8a,0x99,0xa8,0xb7,0xc6,0xf5,0x04,0x13,0x22,0x31,0x40,0x4f,0x5e,0x6d,0x7c,0x8b,0x9a,0xa9,0xb8,0xc7,0xd6},
{0x05,0x14,0x23,0x32,0x41,0x50,0x5f,0x6e,0x7d,0x8c,0x9b,0xaa,0xb9,0xc8,0xd7,0xe6,0x15,0x24,0x33,0x42,0x51,0x60,0x6f,0x7e,0x8d,0x9c,0xab,0xba,0xc9,0xd8,0xe7,0xf6,0x25,0x34,0x43,0x52,0x61,0x70,0x7f,0x8e,0x9d,0xac,0xbb,0xca,0xd9,0xe8,0xf7,0x06,0x35,0x44,0x53,0x62,0x71,0x80,0x8f,0x9e,0xad,0xbc,0xcb,0xda,0xe9,0xf8,0x07,0x16},
{0x45,0x54,0x63,0x72,0x81,0x90,0x9f,0xae,0xbd,0xcc,0xdb,0xea,0xf9,0x08,0x17,0x26,0x55,0x64,0x73,0x82,0x91,0xa0,0xaf,0xbe,0xcd,0xdc,0xeb,0xfa,0x09,0x18,0x27,0x36,0x65,0x74,0x83,0x92,0xa1,0xb0,0xbf,0xce,0xdd,0xec,0xfb,0x0a,0x19,0x28,0x37,0x46,0x75,0x84,0x93,0xa2,0xb1,0xc0,0xcf,0xde,0xed,0xfc,0x0b,0x1a,0x29,0x38,0x47,0x56}
};

struct Vec512 { u64 q[8]; };

static inline Vec512 X(const Vec512& a, const Vec512& k){
    Vec512 r;
    for (int i=0;i<8;i++) r.q[i] = a.q[i] ^ k.q[i];
    return r;
}

static inline Vec512 S_transform(const Vec512& a){
    Vec512 r;
    for (int i=0;i<8;i++){
        u64 x = a.q[i], y = 0;
        for (int b=0;b<8;b++){
            u8 byte = (u8)((x >> (8*b)) & 0xFF);
            y |= ((u64)Sbox[byte]) << (8*b);
        }
        r.q[i] = y;
    }
    return r;
}

static inline Vec512 P_transform(const Vec512& a){
    u8 in[64], out[64];
    for (int i=0;i<8;i++)
        for (int b=0;b<8;b++)
            in[i*8+b] = (u8)((a.q[i] >> (8*b)) & 0xFF);
    for (int i=0;i<64;i++) out[i] = in[Tau[i]];
    Vec512 r;
    for (int i=0;i<8;i++){
        u64 v = 0;
        for (int b=0;b<8;b++) v |= ((u64)out[i*8+b]) << (8*b);
        r.q[i] = v;
    }
    return r;
}

static inline u64 l_transform_u64(u64 x){
    u64 r = 0;
    for (int i=0;i<64;i++)
        if ((x >> (63 - i)) & 1ULL) r ^= A[i];
    return r;
}

static inline Vec512 L_transform(const Vec512& a){
    Vec512 r;
    for (int i=0;i<8;i++) r.q[i] = l_transform_u64(a.q[i]);
    return r;
}

static inline Vec512 LPS(const Vec512& a){
    return L_transform(P_transform(S_transform(a)));
}

static Vec512 g_N(const Vec512& N, const Vec512& h, const Vec512& m){
    Vec512 K = LPS(X(h, N));
    Vec512 state = X(m, K);
    for (int i=0;i<12;i++){
        Vec512 Ci;
        for (int j=0;j<8;j++){
            u64 v = 0;
            for (int b=0;b<8;b++) v |= ((u64)C[i][j*8+b]) << (8*b);
            Ci.q[j] = v;
        }
        Vec512 Kc = LPS(X(K, Ci));
        state = LPS(X(state, Kc));
        K = Kc;
    }
    Vec512 out;
    for (int i=0;i<8;i++) out.q[i] = state.q[i] ^ h.q[i] ^ m.q[i];
    return out;
}

static Vec512 bytes_to_vec512(const u8* b){
    Vec512 v;
    for (int i=0;i<8;i++){
        u64 x = 0;
        for (int j=0;j<8;j++) x |= ((u64)b[i*8+j]) << (8*j);
        v.q[i] = x;
    }
    return v;
}

void hash256(const u8* data, size_t len, u8 out[32]){
    Vec512 h;
    for (int i=0;i<8;i++) h.q[i] = 0x0101010101010101ULL;
    Vec512 N; for (int i=0;i<8;i++) N.q[i] = 0;
    Vec512 Sigma; for (int i=0;i<8;i++) Sigma.q[i] = 0;

    const size_t BLOCK = 64;
    size_t full_blocks = len / BLOCK;
    size_t tail = len % BLOCK;

    for (size_t i=0;i<full_blocks;i++){
        Vec512 m = bytes_to_vec512(data + i*BLOCK);
        h = g_N(N, h, m);
        u64 carry = 512;
        for (int j=0;j<8 && carry;j++){
            u64 sum = N.q[j] + carry;
            carry = (sum < N.q[j]) ? 1 : 0;
            N.q[j] = sum;
        }
        u64 c2 = 0;
        for (int j=0;j<8;j++){
            u64 s = Sigma.q[j] + m.q[j] + c2;
            c2 = (s < Sigma.q[j]) ? 1 : 0;
            Sigma.q[j] = s;
        }
    }

    u8 tail_buf[64] = {0};
    if (tail) memcpy(tail_buf, data + full_blocks*BLOCK, tail);
    tail_buf[tail] = 0x01;

    Vec512 m = bytes_to_vec512(tail_buf);
    h = g_N(N, h, m);

    u64 bits = (u64)tail * 8;
    u64 carry = bits;
    for (int j=0;j<8 && carry;j++){
        u64 sum = N.q[j] + carry;
        carry = (sum < N.q[j]) ? 1 : 0;
        N.q[j] = sum;
    }
    u64 c2 = 0;
    for (int j=0;j<8;j++){
        u64 s = Sigma.q[j] + m.q[j] + c2;
        c2 = (s < Sigma.q[j]) ? 1 : 0;
        Sigma.q[j] = s;
    }

    h = g_N(N, h, Sigma);

    for (int i=0;i<4;i++)
        for (int j=0;j<8;j++)
            out[i*8+j] = (u8)((h.q[i] >> (8*j)) & 0xFF);
}

}

static void mgf1(const u8* seed, size_t seed_len, u8* out, size_t out_len){
    size_t hLen = 32, counter = 0, pos = 0;
    std::vector<u8> buf(seed_len + 4);
    while (pos < out_len){
        u8 C[4] = {
            (u8)((counter >> 24) & 0xFF),
            (u8)((counter >> 16) & 0xFF),
            (u8)((counter >> 8) & 0xFF),
            (u8)(counter & 0xFF)
        };
        if (seed_len) memcpy(buf.data(), seed, seed_len);
        memcpy(buf.data() + seed_len, C, 4);
        u8 h[32];
        Streebog::hash256(buf.data(), buf.size(), h);
        size_t to_copy = (out_len - pos < hLen) ? (out_len - pos) : hLen;
        memcpy(out + pos, h, to_copy);
        pos += to_copy;
        counter++;
    }
}

constexpr size_t RSA_BYTES = 256;
constexpr size_t HASH_BYTES = 32;
constexpr size_t OAEP_MAX_MSG = RSA_BYTES - 2 * HASH_BYTES - 2;

struct RSAPublicKey { BigInt N; BigInt e; };
struct RSAPrivateKey { BigInt N, d, p, q, dp, dq, qinv; };

static void rsa_generate_keys(RSAPublicKey& pub, RSAPrivateKey& priv, std::mt19937_64& rng){
    size_t half = RSA_BYTES * 8 / 2;
    BigInt p, q;
    do { p = generate_prime(half, rng); } while (false);
    do { q = generate_prime(half, rng); } while (q == p);
    BigInt N = p * q;
    BigInt phi = (p - BigInt(1)) * (q - BigInt(1));
    BigInt e(65537);
    BigInt d = mod_inverse(e, phi);
    pub.N = N; pub.e = e;
    priv.N = N; priv.d = d; priv.p = p; priv.q = q;
    priv.dp = d % (p - BigInt(1));
    priv.dq = d % (q - BigInt(1));
    priv.qinv = mod_inverse(q, p);
}

static BigInt rsa_encrypt_raw(const BigInt& m, const RSAPublicKey& pub){
    return mod_pow(m, pub.e, pub.N);
}

static BigInt rsa_decrypt_crt(const BigInt& c, const RSAPrivateKey& priv){
    BigInt m1 = mod_pow_ct(c % priv.p, priv.dp, priv.p);
    BigInt m2 = mod_pow_ct(c % priv.q, priv.dq, priv.q);
    BigInt diff = m1 - m2;
    int neg = (diff < BigInt(0)) ? 1 : 0;
    BigInt adjusted = m1 + BigInt(neg) * priv.p;
    BigInt h = (priv.qinv * (adjusted - m2)) % priv.p;
    return m2 + h * priv.q;
}

static void oaep_encode(const u8* M, size_t mLen, const u8* label, size_t labelLen,
                        u8* EM, std::mt19937_64& rng){
    if (mLen > OAEP_MAX_MSG) throw std::runtime_error("OAEP: message too long");
    size_t hLen = HASH_BYTES;
    size_t dbLen = RSA_BYTES - hLen - 1;

    u8 lHash[32];
    Streebog::hash256(label, labelLen, lHash);

    std::vector<u8> DB(dbLen, 0);
    memcpy(DB.data(), lHash, hLen);
    size_t psLen = dbLen - hLen - 1 - mLen;
    DB[hLen + psLen] = 0x01;
    if (mLen) memcpy(DB.data() + hLen + psLen + 1, M, mLen);

    u8 seed[32];
    for (size_t i=0;i<hLen;i += 8){
        u64 r = rng();
        size_t chunk = (hLen - i < 8) ? (hLen - i) : 8;
        memcpy(seed + i, &r, chunk);
    }

    std::vector<u8> dbMask(dbLen);
    mgf1(seed, hLen, dbMask.data(), dbLen);

    std::vector<u8> maskedDB(dbLen);
    for (size_t i=0;i<dbLen;i++) maskedDB[i] = DB[i] ^ dbMask[i];

    u8 seedMask[32];
    mgf1(maskedDB.data(), dbLen, seedMask, hLen);

    u8 maskedSeed[32];
    for (size_t i=0;i<hLen;i++) maskedSeed[i] = seed[i] ^ seedMask[i];

    EM[0] = 0x00;
    memcpy(EM + 1, maskedSeed, hLen);
    memcpy(EM + 1 + hLen, maskedDB.data(), dbLen);
}

static size_t oaep_decode(const u8* EM, const u8* label, size_t labelLen, u8* M_out){
    size_t hLen = HASH_BYTES;
    size_t dbLen = RSA_BYTES - hLen - 1;

    u8 err = 0;
    err |= EM[0];

    const u8* maskedSeed = EM + 1;
    const u8* maskedDB = EM + 1 + hLen;

    u8 seedMask[32];
    mgf1(maskedDB, dbLen, seedMask, hLen);

    u8 seed[32];
    for (size_t i=0;i<hLen;i++) seed[i] = maskedSeed[i] ^ seedMask[i];

    std::vector<u8> dbMask(dbLen);
    mgf1(seed, hLen, dbMask.data(), dbLen);

    std::vector<u8> DB(dbLen);
    for (size_t i=0;i<dbLen;i++) DB[i] = maskedDB[i] ^ dbMask[i];

    u8 lHash[32];
    Streebog::hash256(label, labelLen, lHash);

    err |= ct_memcmp(DB.data(), lHash, hLen);

    size_t msg_offset = 0;
    u8 found = 0;
    for (size_t i = hLen; i < dbLen; ++i){
        u8 is_one = (u8)((DB[i] == 0x01) ? 0xFF : 0x00);
        u8 take = (u8)(is_one & ~found);
        u32 new_off = (u32)(i + 1);
        u32 old_off = (u32)msg_offset;
        u8 mask_full = (u8)(take ? 0xFF : 0x00);
        u32 chosen = (mask_full & new_off) | ((u8)(~mask_full) & old_off);
        msg_offset = (size_t)chosen;
        found |= is_one;
    }
    err |= (u8)(found ^ 0xFF);

    size_t msg_len = (msg_offset <= dbLen) ? (dbLen - msg_offset) : 0;
    for (size_t i=0;i<OAEP_MAX_MSG;i++){
        u8 in_range = (u8)((i < msg_len) ? 0xFF : 0x00);
        u8 byte = (i < msg_len) ? DB[msg_offset + i] : 0;
        M_out[i] = ct_select_u8(in_range, byte, 0);
    }

    return (err == 0) ? msg_len : 0;
}

static bool fault_check(const BigInt& m, const BigInt& c, const RSAPublicKey& pub){
    BigInt c_check = mod_pow(m, pub.e, pub.N);
    std::vector<u8> a(RSA_BYTES), b(RSA_BYTES);
    c_check.to_bytes(a.data(), RSA_BYTES);
    c.to_bytes(b.data(), RSA_BYTES);
    return ct_memcmp(a.data(), b.data(), RSA_BYTES) == 0;
}

static void rsa_oaep_encrypt(const u8* M, size_t mLen,
                             const u8* label, size_t labelLen,
                             const RSAPublicKey& pub,
                             u8* c_out, std::mt19937_64& rng){
    std::vector<u8> EM(RSA_BYTES);
    oaep_encode(M, mLen, label, labelLen, EM.data(), rng);
    BigInt m = BigInt::from_bytes(EM.data(), RSA_BYTES);
    if (m >= pub.N) throw std::runtime_error("OAEP: EM >= N");
    BigInt c = rsa_encrypt_raw(m, pub);
    c.to_bytes(c_out, RSA_BYTES);
}

static size_t rsa_oaep_decrypt(const u8* c_in,
                               const u8* label, size_t labelLen,
                               const RSAPrivateKey& priv,
                               const RSAPublicKey& pub,
                               u8* M_out){
    BigInt c = BigInt::from_bytes(c_in, RSA_BYTES);
    if (c >= priv.N) return 0;
    BigInt m = rsa_decrypt_crt(c, priv);
    if (!fault_check(m, c, pub)) return 0;
    std::vector<u8> EM(RSA_BYTES);
    m.to_bytes(EM.data(), RSA_BYTES);
    return oaep_decode(EM.data(), label, labelLen, M_out);
}

static size_t rsa_oaep_decrypt_safe(const u8* c_in,
                                    const u8* label, size_t labelLen,
                                    const RSAPrivateKey& priv,
                                    const RSAPublicKey& pub,
                                    u8* M_out){
    try {
        return rsa_oaep_decrypt(c_in, label, labelLen, priv, pub, M_out);
    } catch (const std::exception& e) {
        fprintf(stderr, "  [decrypt exception] %s\n", e.what());
        return 0;
    } catch (...) {
        fprintf(stderr, "  [decrypt unknown exception]\n");
        return 0;
    }
}

int main(){
    std::mt19937_64 rng(0xC0FFEE);

    printf("=== Лабораторная работа №2, вариант 6 ===\n");
    printf("RSA-%zu, Стрибог-256, OAEP, CRT, Constant-time, Fault Injection\n\n", RSA_BYTES * 8);
    fflush(stdout);

    printf("[*] Генерация ключей RSA-%zu...\n", RSA_BYTES * 8);
    fflush(stdout);
    RSAPublicKey pub; RSAPrivateKey priv;
    rsa_generate_keys(pub, priv, rng);
    printf("    N (bits) = %zu\n", pub.N.bit_length());
    printf("    e        = %s\n", pub.e.to_string().c_str());
    fflush(stdout);

    {
        const char* msg = "Hello, RSA-OAEP + Fault Injection!";
        std::vector<u8> M(OAEP_MAX_MSG);
        size_t mLen = strlen(msg);
        memcpy(M.data(), msg, mLen);
        std::vector<u8> c(RSA_BYTES), M2(OAEP_MAX_MSG);
        rsa_oaep_encrypt(M.data(), mLen, nullptr, 0, pub, c.data(), rng);
        size_t mLen2 = rsa_oaep_decrypt_safe(c.data(), nullptr, 0, priv, pub, M2.data());
        printf("\n[Тест 1] Обычное сообщение (%zu байт)\n", mLen);
        printf("    Расшифровано: %zu байт\n", mLen2);
        printf("    Результат: %s\n",
               (mLen2 == mLen && memcmp(M.data(), M2.data(), mLen) == 0) ? "OK" : "FAIL");
        fflush(stdout);
    }

    {
        printf("\n[Тест 2] Граничные условия\n");
        fflush(stdout);
        {
            std::vector<u8> c(RSA_BYTES), M2(OAEP_MAX_MSG);
            rsa_oaep_encrypt(nullptr, 0, nullptr, 0, pub, c.data(), rng);
            size_t mLen = rsa_oaep_decrypt_safe(c.data(), nullptr, 0, priv, pub, M2.data());
            printf("    len=0: получено %zu -> %s\n", mLen,
                   (mLen == 0) ? "OK" : "FAIL");
            fflush(stdout);
        }
        {
            std::vector<u8> M(OAEP_MAX_MSG);
            for (size_t i=0;i<M.size();i++) M[i] = (u8)(i & 0xFF);
            std::vector<u8> c(RSA_BYTES), M2(OAEP_MAX_MSG);
            rsa_oaep_encrypt(M.data(), M.size(), nullptr, 0, pub, c.data(), rng);
            size_t mLen = rsa_oaep_decrypt_safe(c.data(), nullptr, 0, priv, pub, M2.data());
            bool ok = (mLen == OAEP_MAX_MSG) && (memcmp(M.data(), M2.data(), mLen) == 0);
            printf("    len=%zu (max): получено %zu -> %s\n",
                   OAEP_MAX_MSG, mLen, ok ? "OK" : "FAIL");
            fflush(stdout);
        }
        {
            std::vector<u8> M(OAEP_MAX_MSG + 1, 0xAA);
            std::vector<u8> c(RSA_BYTES);
            bool caught = false;
            try { rsa_oaep_encrypt(M.data(), M.size(), nullptr, 0, pub, c.data(), rng); }
            catch (const std::exception&) { caught = true; }
            printf("    len=%zu (>max): исключение -> %s\n",
                   OAEP_MAX_MSG + 1, caught ? "OK" : "FAIL");
            fflush(stdout);
        }
    }

    {
        printf("\n[Тест 3] Fault Injection защита\n");
        fflush(stdout);
        const char* msg = "Fault injection test";
        std::vector<u8> M(OAEP_MAX_MSG);
        size_t mLen = strlen(msg);
        memcpy(M.data(), msg, mLen);
        std::vector<u8> c(RSA_BYTES);
        rsa_oaep_encrypt(M.data(), mLen, nullptr, 0, pub, c.data(), rng);
        std::vector<u8> c_faulty(c);
        c_faulty[RSA_BYTES/2] ^= 0x01;
        std::vector<u8> M2(OAEP_MAX_MSG);
        size_t r1 = rsa_oaep_decrypt_safe(c.data(), nullptr, 0, priv, pub, M2.data());
        size_t r2 = rsa_oaep_decrypt_safe(c_faulty.data(), nullptr, 0, priv, pub, M2.data());
        printf("    Валидный:      %zu байт -> %s\n",
               r1, (r1 == mLen) ? "OK" : "FAIL");
        printf("    Повреждённый:  %zu байт -> %s\n",
               r2, (r2 == 0) ? "OK (отклонён)" : "FAIL");
        fflush(stdout);
    }

    {
        printf("\n[Тест 4] Constant-time оценка (10 прогонов)\n");
        fflush(stdout);
        const char* msg = "CT test";
        std::vector<u8> M(OAEP_MAX_MSG);
        size_t mLen = strlen(msg);
        memcpy(M.data(), msg, mLen);
        std::vector<u8> c(RSA_BYTES), c_bad(RSA_BYTES);
        rsa_oaep_encrypt(M.data(), mLen, nullptr, 0, pub, c.data(), rng);
        memcpy(c_bad.data(), c.data(), RSA_BYTES);
        c_bad[100] ^= 0xFF;
        std::vector<u8> M2(OAEP_MAX_MSG);

        auto t0 = std::chrono::high_resolution_clock::now();
        for (int i=0;i<10;i++) rsa_oaep_decrypt_safe(c.data(), nullptr, 0, priv, pub, M2.data());
        auto t1 = std::chrono::high_resolution_clock::now();
        for (int i=0;i<10;i++) rsa_oaep_decrypt_safe(c_bad.data(), nullptr, 0, priv, pub, M2.data());
        auto t2 = std::chrono::high_resolution_clock::now();

        double dt_ok  = std::chrono::duration<double, std::milli>(t1 - t0).count() / 10.0;
        double dt_bad = std::chrono::duration<double, std::milli>(t2 - t1).count() / 10.0;
        printf("    Валидный:      %.3f мс\n", dt_ok);
        printf("    Повреждённый:  %.3f мс\n", dt_bad);
        printf("    Разница:       %.3f мс (%.2f%%)\n",
               dt_bad - dt_ok, 100.0 * (dt_bad - dt_ok) / dt_ok);
        fflush(stdout);
    }

    printf("\n=== Готово ===\n");
    return 0;
}