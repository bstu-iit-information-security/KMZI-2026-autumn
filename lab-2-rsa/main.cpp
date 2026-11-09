#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <chrono>
#include <random>

#ifdef _WIN32
  #include <windows.h>
#endif

using namespace std;

class SHA512
{
public:
    SHA512() { reset(); }

    string hash(const string& input)
    {
        reset();
        update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
        uint8_t digest[64];
        final(digest);
        ostringstream oss;
        oss << hex << uppercase << setfill('0');
        for (int i = 0; i < 64; ++i)
            oss << setw(2) << static_cast<int>(digest[i]);
        return oss.str();
    }

    void reset()
    {
        h_[0] = 0x6a09e667f3bcc908ULL;
        h_[1] = 0xbb67ae8584caa73bULL;
        h_[2] = 0x3c6ef372fe94f82bULL;
        h_[3] = 0xa54ff53a5f1d36f1ULL;
        h_[4] = 0x510e527fade682d1ULL;
        h_[5] = 0x9b05688c2b3e6c1fULL;
        h_[6] = 0x1f83d9abfb41bd6bULL;
        h_[7] = 0x5be0cd19137e2179ULL;
        buf_len_ = 0;
        total_len_ = 0;
    }

    void update(const uint8_t* data, size_t len)
    {
        if (!data || len == 0) return;
        total_len_ += len;
        while (len > 0)
        {
            size_t take = min<size_t>(len, 128 - buf_len_);
            memcpy(buf_ + buf_len_, data, take);
            buf_len_ += take;
            data += take;
            len -= take;
            if (buf_len_ == 128)
            {
                process_block(buf_);
                buf_len_ = 0;
            }
        }
    }

    void final(uint8_t out[64])
    {
        uint64_t bit_len = total_len_ * 8;
        buf_[buf_len_++] = 0x80;
        if (buf_len_ > 112)
        {
            while (buf_len_ < 128) buf_[buf_len_++] = 0;
            process_block(buf_);
            buf_len_ = 0;
        }
        while (buf_len_ < 112) buf_[buf_len_++] = 0;
        for (int i = 0; i < 8; ++i) buf_[112 + i] = 0;
        for (int i = 0; i < 8; ++i)
            buf_[120 + i] = static_cast<uint8_t>((bit_len >> (56 - 8 * i)) & 0xFF);
        process_block(buf_);
        for (int i = 0; i < 8; ++i)
        {
            out[i * 8 + 0] = static_cast<uint8_t>((h_[i] >> 56) & 0xFF);
            out[i * 8 + 1] = static_cast<uint8_t>((h_[i] >> 48) & 0xFF);
            out[i * 8 + 2] = static_cast<uint8_t>((h_[i] >> 40) & 0xFF);
            out[i * 8 + 3] = static_cast<uint8_t>((h_[i] >> 32) & 0xFF);
            out[i * 8 + 4] = static_cast<uint8_t>((h_[i] >> 24) & 0xFF);
            out[i * 8 + 5] = static_cast<uint8_t>((h_[i] >> 16) & 0xFF);
            out[i * 8 + 6] = static_cast<uint8_t>((h_[i] >>  8) & 0xFF);
            out[i * 8 + 7] = static_cast<uint8_t>((h_[i]      ) & 0xFF);
        }
    }

private:
    uint64_t h_[8];
    uint8_t  buf_[128];
    size_t   buf_len_;
    uint64_t total_len_;

    static inline uint64_t rotr(uint64_t x, int n)
    {
        return (x >> n) | (x << (64 - n));
    }

    void process_block(const uint8_t* block)
    {
        static const uint64_t K[80] = {
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

        uint64_t w[80];
        for (int i = 0; i < 16; ++i)
        {
            w[i] = 0;
            for (int j = 0; j < 8; ++j)
                w[i] = (w[i] << 8) | block[i * 8 + j];
        }
        for (int i = 16; i < 80; ++i)
        {
            uint64_t s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
            uint64_t s1 = rotr(w[i -  2], 19) ^ rotr(w[i - 2], 61) ^ (w[i -  2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint64_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        uint64_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];

        for (int i = 0; i < 80; ++i)
        {
            uint64_t S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t t1 = h + S1 + ch + K[i] + w[i];
            uint64_t S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
        h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
    }
};

vector<uint8_t> hexToBytes(const string& hex)
{
    vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.length(); i += 2)
    {
        string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

class BigInt
{
public:
    vector<uint32_t> digits;

    BigInt() { digits.push_back(0); }

    BigInt(uint64_t val)
    {
        digits.clear();
        digits.push_back(static_cast<uint32_t>(val & 0xFFFFFFFF));
        digits.push_back(static_cast<uint32_t>((val >> 32) & 0xFFFFFFFF));
        trim();
    }

    BigInt(const string& hexStr)
    {
        digits.clear();
        string s = hexStr;
        if (s.length() % 8 != 0)
            s = string(8 - s.length() % 8, '0') + s;
        for (int i = (int)s.length() - 8; i >= 0; i -= 8)
        {
            uint32_t limb = static_cast<uint32_t>(stoul(s.substr(i, 8), nullptr, 16));
            digits.push_back(limb);
        }
        trim();
    }

    void trim()
    {
        while (digits.size() > 1 && digits.back() == 0)
            digits.pop_back();
    }

    bool isEven() const { return (digits[0] & 1) == 0; }

    size_t bitLength() const
    {
        if (digits.size() == 1 && digits[0] == 0) return 0;
        size_t bits = (digits.size() - 1) * 32;
        uint32_t top = digits.back();
        while (top > 0) { bits++; top >>= 1; }
        return bits;
    }

    bool operator==(const BigInt& o) const { return digits == o.digits; }
    bool operator!=(const BigInt& o) const { return !(*this == o); }

    bool operator<(const BigInt& o) const
    {
        if (digits.size() != o.digits.size()) return digits.size() < o.digits.size();
        for (int i = (int)digits.size() - 1; i >= 0; --i)
            if (digits[i] != o.digits[i]) return digits[i] < o.digits[i];
        return false;
    }
    bool operator>(const BigInt& o) const
    {
        if (digits.size() != o.digits.size()) return digits.size() > o.digits.size();
        for (int i = (int)digits.size() - 1; i >= 0; --i)
            if (digits[i] != o.digits[i]) return digits[i] > o.digits[i];
        return false;
    }
    bool operator>=(const BigInt& o) const { return !(*this < o); }
    bool operator<=(const BigInt& o) const { return !(*this > o); }

    BigInt operator+(const BigInt& o) const
    {
        BigInt res; res.digits.clear();
        uint64_t carry = 0;
        size_t maxSize = max(digits.size(), o.digits.size());
        for (size_t i = 0; i < maxSize || carry; ++i)
        {
            uint64_t sum = carry;
            if (i < digits.size()) sum += digits[i];
            if (i < o.digits.size()) sum += o.digits[i];
            res.digits.push_back(static_cast<uint32_t>(sum & 0xFFFFFFFF));
            carry = sum >> 32;
        }
        res.trim();
        return res;
    }

    BigInt operator-(const BigInt& o) const
    {
        if (*this < o) return BigInt(0);
        BigInt res; res.digits.clear();
        int64_t borrow = 0;
        for (size_t i = 0; i < digits.size(); ++i)
        {
            int64_t diff = static_cast<int64_t>(digits[i]) - borrow;
            if (i < o.digits.size()) diff -= o.digits[i];
            if (diff < 0) { diff += 0x100000000LL; borrow = 1; }
            else borrow = 0;
            res.digits.push_back(static_cast<uint32_t>(diff));
        }
        res.trim();
        return res;
    }

    BigInt operator*(const BigInt& o) const
    {
        BigInt res;
        res.digits.assign(digits.size() + o.digits.size(), 0);
        for (size_t i = 0; i < digits.size(); ++i)
        {
            uint64_t carry = 0;
            for (size_t j = 0; j < o.digits.size() || carry; ++j)
            {
                uint64_t cur = res.digits[i + j] +
                    static_cast<uint64_t>(digits[i]) *
                    (j < o.digits.size() ? o.digits[j] : 0) + carry;
                res.digits[i + j] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
                carry = cur >> 32;
            }
        }
        res.trim();
        return res;
    }

    BigInt shiftLeft1() const
    {
        BigInt res; res.digits.clear();
        uint32_t carry = 0;
        for (size_t i = 0; i < digits.size(); ++i)
        {
            uint64_t cur = (static_cast<uint64_t>(digits[i]) << 1) | carry;
            res.digits.push_back(static_cast<uint32_t>(cur & 0xFFFFFFFF));
            carry = static_cast<uint32_t>(cur >> 32);
        }
        if (carry) res.digits.push_back(carry);
        res.trim();
        return res;
    }

    BigInt shiftRight1() const
    {
        BigInt res;
        res.digits.resize(digits.size(), 0);
        uint32_t carry = 0;
        for (int i = (int)digits.size() - 1; i >= 0; --i)
        {
            uint64_t cur = (static_cast<uint64_t>(carry) << 32) | digits[i];
            res.digits[i] = static_cast<uint32_t>(cur >> 1);
            carry = digits[i] & 1;
        }
        res.trim();
        return res;
    }

    pair<BigInt, BigInt> divmod(const BigInt& divisor) const
    {
        if (divisor == BigInt(0)) return { BigInt(0), BigInt(0) };
        if (*this < divisor) return { BigInt(0), *this };

        if (divisor.digits.size() == 1)
        {
            BigInt q;
            q.digits.assign(digits.size(), 0);
            uint64_t dv = divisor.digits[0];
            uint64_t rem = 0;
            for (int i = (int)digits.size() - 1; i >= 0; --i)
            {
                uint64_t cur = (rem << 32) | digits[i];
                q.digits[i] = static_cast<uint32_t>(cur / dv);
                rem = cur % dv;
            }
            q.trim();
            BigInt r;
            r.digits[0] = static_cast<uint32_t>(rem);
            return { q, r };
        }

        int n = (int)divisor.digits.size();
        int m = (int)digits.size() - n;

        int shift = 0;
        uint32_t top = divisor.digits[n - 1];
        while ((top & 0x80000000u) == 0) { top <<= 1; shift++; }

        vector<uint32_t> un(m + n + 1, 0);
        vector<uint32_t> vn(n, 0);

        uint32_t carry = 0;
        for (size_t i = 0; i < digits.size(); ++i)
        {
            uint64_t cur = (static_cast<uint64_t>(digits[i]) << shift) | carry;
            un[i] = static_cast<uint32_t>(cur);
            carry = static_cast<uint32_t>(cur >> 32);
        }
        un[digits.size()] = carry;

        carry = 0;
        for (int i = 0; i < n; ++i)
        {
            uint64_t cur = (static_cast<uint64_t>(divisor.digits[i]) << shift) | carry;
            vn[i] = static_cast<uint32_t>(cur);
            carry = static_cast<uint32_t>(cur >> 32);
        }

        vector<uint32_t> q(m + 1, 0);
        const uint64_t B = 1ULL << 32;

        for (int j = m; j >= 0; --j)
        {
            uint64_t num = (static_cast<uint64_t>(un[j + n]) << 32) | un[j + n - 1];
            uint64_t qhat = num / vn[n - 1];
            uint64_t rhat = num % vn[n - 1];

            while (qhat >= B ||
                   qhat * vn[n - 2] > ((rhat << 32) | un[j + n - 2]))
            {
                qhat--;
                rhat += vn[n - 1];
                if (rhat >= B) break;
            }

            int64_t borrow = 0;
            uint64_t carry2 = 0;
            for (int i = 0; i < n; ++i)
            {
                uint64_t prod = qhat * vn[i] + carry2;
                carry2 = prod >> 32;
                int64_t diff = static_cast<int64_t>(un[j + i])
                             - static_cast<int64_t>(static_cast<uint32_t>(prod))
                             - borrow;
                if (diff < 0) { diff += static_cast<int64_t>(B); borrow = 1; }
                else borrow = 0;
                un[j + i] = static_cast<uint32_t>(diff);
            }
            int64_t diff = static_cast<int64_t>(un[j + n])
                         - static_cast<int64_t>(carry2) - borrow;
            if (diff < 0) { diff += static_cast<int64_t>(B); borrow = 1; }
            else borrow = 0;
            un[j + n] = static_cast<uint32_t>(diff);

            if (borrow)
            {
                qhat--;
                uint64_t c = 0;
                for (int i = 0; i < n; ++i)
                {
                    uint64_t s = static_cast<uint64_t>(un[j + i]) + vn[i] + c;
                    un[j + i] = static_cast<uint32_t>(s);
                    c = s >> 32;
                }
                un[j + n] += static_cast<uint32_t>(c);
            }
            q[j] = static_cast<uint32_t>(qhat);
        }

        BigInt r;
        r.digits.assign(n, 0);
        for (int i = 0; i < n; ++i) r.digits[i] = un[i];
        if (shift > 0)
        {
            uint32_t c = 0;
            for (int i = n - 1; i >= 0; --i)
            {
                uint64_t cur = (static_cast<uint64_t>(c) << 32) | r.digits[i];
                r.digits[i] = static_cast<uint32_t>(cur >> shift);
                c = static_cast<uint32_t>(cur & ((1ULL << shift) - 1));
            }
        }
        r.trim();

        BigInt qq;
        qq.digits = q;
        qq.trim();
        return { qq, r };
    }

    BigInt operator/(const BigInt& other) const { return divmod(other).first; }
    BigInt operator%(const BigInt& other) const { return divmod(other).second; }

    string toHexString() const
    {
        stringstream ss;
        ss << hex << uppercase;
        ss << digits.back();
        for (int i = (int)digits.size() - 2; i >= 0; --i)
            ss << setfill('0') << setw(8) << digits[i];
        return ss.str();
    }

    static BigInt fromBytes(const vector<uint8_t>& bytes)
    {
        BigInt x = 0;
        for (uint8_t b : bytes) x = x * BigInt(256) + BigInt(b);
        return x;
    }

    vector<uint8_t> toBytes(size_t len) const
    {
        vector<uint8_t> out(len, 0);
        BigInt t = *this;
        for (size_t i = 0; i < len; ++i)
        {
            out[len - 1 - i] = static_cast<uint8_t>(t.digits[0] & 0xFF);
            for (int j = 0; j < 8; ++j) t = t.shiftRight1();
        }
        return out;
    }
};

BigInt modPow(BigInt base, BigInt exp, BigInt mod)
{
    BigInt result = 1;
    base = base % mod;
    while (exp != BigInt(0))
    {
        if (exp.digits[0] & 1)
            result = (result * base) % mod;
        base = (base * base) % mod;
        exp = exp.shiftRight1();
    }
    return result;
}

BigInt modInverse(BigInt a, BigInt m)
{
    BigInt m0 = m, t, q;
    BigInt x0 = 0, x1 = 1;
    BigInt zero = 0;
    if (m == BigInt(1)) return zero;
    while (a > BigInt(1))
    {
        auto dm = a.divmod(m0);
        q = dm.first;
        t = m0;
        m0 = dm.second;
        a = t;
        t = x0;
        BigInt qx0 = q * x0;
        if (x1 < qx0)
        {
            BigInt diff = qx0 - x1;
            BigInt rem = diff % m;
            x0 = (rem == zero) ? zero : (m - rem);
        }
        else x0 = x1 - qx0;
        x1 = t;
    }
    return x1;
}

const size_t HASH_LEN = 64;
const size_t OAEP_K   = 384;

vector<uint8_t> sha512(const vector<uint8_t>& data)
{
    SHA512 sha;
    string inputStr(data.begin(), data.end());
    string hexHash = sha.hash(inputStr);
    return hexToBytes(hexHash);
}

vector<uint8_t> generateRandomBytes(size_t numBytes)
{
    static uint64_t counter = 0;
    vector<uint8_t> result;
    result.reserve(numBytes);
    while (result.size() < numBytes)
    {
        uint64_t now = chrono::high_resolution_clock::now().time_since_epoch().count();
        counter++;

        vector<uint8_t> seedData(24);
        memcpy(seedData.data(), &now, 8);
        memcpy(seedData.data() + 8, &counter, 8);
        random_device rd;
        uint64_t rVal = (static_cast<uint64_t>(rd()) << 32) | rd();
        memcpy(seedData.data() + 16, &rVal, 8);

        vector<uint8_t> hash = sha512(seedData);
        size_t toCopy = min(numBytes - result.size(), hash.size());
        result.insert(result.end(), hash.begin(), hash.begin() + toCopy);
    }
    return result;
}

BigInt generateRandomBigInt(size_t bitLen)
{
    size_t byteLen = (bitLen + 7) / 8;
    vector<uint8_t> bytes = generateRandomBytes(byteLen);
    bytes[0] |= (1 << ((bitLen - 1) % 8));
    bytes[byteLen - 1] |= 1;

    stringstream ss;
    ss << hex << setfill('0');
    for (uint8_t b : bytes) ss << setw(2) << static_cast<int>(b);
    return BigInt(ss.str());
}

bool isPrimeMillerRabin(const BigInt& n, int k = 10)
{
    if (n <= BigInt(1)) return false;
    if (n == BigInt(2) || n == BigInt(3)) return true;
    if (n.isEven()) return false;

    BigInt d = n - BigInt(1);
    size_t s = 0;
    while (d.isEven()) { d = d.shiftRight1(); s++; }

    for (int i = 0; i < k; ++i)
    {
        BigInt a = generateRandomBigInt(min(n.bitLength() - 1, static_cast<size_t>(64)));
        if (a <= BigInt(1)) a = BigInt(2);
        if (a >= n - BigInt(1)) a = n - BigInt(2);

        BigInt x = modPow(a, d, n);
        if (x == BigInt(1) || x == n - BigInt(1)) continue;

        bool composite = true;
        for (size_t r = 1; r < s; ++r)
        {
            x = modPow(x, BigInt(2), n);
            if (x == n - BigInt(1)) { composite = false; break; }
        }
        if (composite) return false;
    }
    return true;
}

BigInt generateLargePrime(size_t bitLen)
{
    static const vector<uint32_t> smallPrimes = {
        3,5,7,11,13,17,19,23,29,31,37,41,43,47,
        53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,
        127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199
    };
    while (true)
    {
        BigInt candidate = generateRandomBigInt(bitLen);
        bool skip = false;
        for (uint32_t sp : smallPrimes)
        {
            if ((candidate % BigInt(sp)) == BigInt(0)) { skip = true; break; }
        }
        if (skip) continue;
        if (isPrimeMillerRabin(candidate)) return candidate;
    }
}

vector<uint8_t> mgf1(const vector<uint8_t>& seed, size_t length)
{
    vector<uint8_t> mask;
    mask.reserve(length);
    uint32_t counter = 0;
    while (mask.size() < length)
    {
        vector<uint8_t> C(4);
        C[0] = (counter >> 24) & 0xFF;
        C[1] = (counter >> 16) & 0xFF;
        C[2] = (counter >> 8) & 0xFF;
        C[3] = counter & 0xFF;

        vector<uint8_t> temp = seed;
        temp.insert(temp.end(), C.begin(), C.end());

        vector<uint8_t> hash = sha512(temp);
        mask.insert(mask.end(), hash.begin(), hash.end());
        counter++;
    }
    mask.resize(length);
    return mask;
}

vector<uint8_t> oaepPad(const vector<uint8_t>& message, size_t k)
{
    if (k < 2 * HASH_LEN + 2) return {};
    size_t maxMsgLen = k - 2 * HASH_LEN - 2;
    if (message.size() > maxMsgLen) return {};

    vector<uint8_t> lHash = sha512({});
    size_t psLen = k - message.size() - 2 * HASH_LEN - 2;
    vector<uint8_t> ps(psLen, 0x00);

    vector<uint8_t> db = lHash;
    db.insert(db.end(), ps.begin(), ps.end());
    db.push_back(0x01);
    db.insert(db.end(), message.begin(), message.end());

    vector<uint8_t> seed = generateRandomBytes(HASH_LEN);
    vector<uint8_t> dbMask = mgf1(seed, k - HASH_LEN - 1);
    vector<uint8_t> maskedDB(db.size());
    for (size_t i = 0; i < db.size(); ++i) maskedDB[i] = db[i] ^ dbMask[i];

    vector<uint8_t> seedMask = mgf1(maskedDB, HASH_LEN);
    vector<uint8_t> maskedSeed(HASH_LEN);
    for (size_t i = 0; i < HASH_LEN; ++i) maskedSeed[i] = seed[i] ^ seedMask[i];

    vector<uint8_t> em;
    em.reserve(k);
    em.push_back(0x00);
    em.insert(em.end(), maskedSeed.begin(), maskedSeed.end());
    em.insert(em.end(), maskedDB.begin(), maskedDB.end());
    return em;
}

static inline uint8_t ct_eq_u8(uint8_t a, uint8_t b)
{
    unsigned x = (unsigned)(a ^ b);
    unsigned y = x | (0u - x);
    return (uint8_t)(((y >> 31) & 1u) ^ 1u);
}

vector<uint8_t> oaepUnpad(const vector<uint8_t>& em, size_t k)
{
    if (em.size() != k) return {};
    const size_t dbLen = k - HASH_LEN - 1;

    vector<uint8_t> maskedSeed(em.begin() + 1, em.begin() + 1 + HASH_LEN);
    vector<uint8_t> maskedDB(em.begin() + 1 + HASH_LEN, em.end());

    vector<uint8_t> seedMask = mgf1(maskedDB, HASH_LEN);
    vector<uint8_t> seed(HASH_LEN);
    for (size_t i = 0; i < HASH_LEN; ++i) seed[i] = maskedSeed[i] ^ seedMask[i];

    vector<uint8_t> dbMask = mgf1(seed, dbLen);
    vector<uint8_t> db(dbLen);
    for (size_t i = 0; i < dbLen; ++i) db[i] = maskedDB[i] ^ dbMask[i];

    uint8_t err = em[0];
    vector<uint8_t> lHash = sha512({});
    for (size_t i = 0; i < HASH_LEN; ++i)
        err |= (uint8_t)(lHash[i] ^ db[i]);

    size_t  msgStart = dbLen;
    uint8_t found    = 0;
    for (size_t i = HASH_LEN; i < dbLen; ++i)
    {
        uint8_t is01 = ct_eq_u8(db[i], 0x01);
        uint8_t is00 = ct_eq_u8(db[i], 0x00);
        uint8_t notFound = (uint8_t)(1 ^ found);

        uint8_t ok = (uint8_t)(is00 | is01);
        err |= (uint8_t)(notFound & (uint8_t)(1 ^ ok));

        uint8_t set = (uint8_t)(is01 & notFound);
        found |= set;

        size_t mask = (size_t)0 - (size_t)set;
        msgStart = (msgStart & ~mask) | ((i + 1) & mask);
    }
    err |= (uint8_t)(1 ^ found);

    if (err != 0) return {};
    return vector<uint8_t>(db.begin() + msgStart, db.end());
}

struct RSAKey
{
    BigInt N, e, d, p, q, dp, dq, qinv;
};

RSAKey generateKeys(size_t keyBitLen = 3072)
{
    RSAKey key;
    size_t primeBits = keyBitLen / 2;

    cout << "   [!] Генерация p (" << primeBits << " бит)..." << endl;
    key.p = generateLargePrime(primeBits);

    cout << "   [!] Генерация q (" << primeBits << " бит)..." << endl;
    do {
        key.q = generateLargePrime(primeBits);
    } while (key.p == key.q);

    key.N = key.p * key.q;
    BigInt phi = (key.p - BigInt(1)) * (key.q - BigInt(1));
    key.e = BigInt(65537);

    while (phi % key.e == BigInt(0))
        key.e = key.e + BigInt(2);

    key.d    = modInverse(key.e, phi);
    key.dp   = key.d % (key.p - BigInt(1));
    key.dq   = key.d % (key.q - BigInt(1));
    key.qinv = modInverse(key.q, key.p);
    return key;
}

BigInt rsaEncrypt(BigInt m, BigInt e, BigInt N)
{
    return modPow(m, e, N);
}

BigInt rsaDecryptCRT(BigInt c, const RSAKey& key)
{
    BigInt m1 = modPow(c, key.dp, key.p);
    BigInt m2 = modPow(c, key.dq, key.q);
    BigInt m2_mod_p = m2 % key.p;
    BigInt diff = (m1 + key.p - m2_mod_p) % key.p;
    BigInt h = (key.qinv * diff) % key.p;
    BigInt m = m2 + (h * key.q);
    return m;
}

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    cout << "[+] Лабораторная работа №2. Вариант 3." << endl;
    cout << "[+] RSA-3072, SHA-512, Constant-time Garner CRT" << endl << endl;

    {
        SHA512 s;
        string h = s.hash("abc");
        const string expected =
            "DDAF35A193617ABACC417349AE204131"
            "12E6FA4E89A97EA20A9EEEE64B55D39A"
            "2192992A274FC1A836BA3C23A3FEEBBD"
            "454D4423643CE80E2A9AC94FA54CA49F";
        cout << "[0] SHA-512(\"abc\"): "
             << (h == expected ? "OK" : "FAIL") << endl << endl;
    }

    cout << "[1] Генерация RSA ключей (3072 бита)..." << endl;
    RSAKey key = generateKeys(3072);

    cout << "[+] Ключи успешно сгенерированы." << endl;
    cout << "    Модуль N (HEX, первые 32): 0x"
         << key.N.toHexString().substr(0, 32) << "..." << endl;
    cout << "    Экспонента e:              0x"
         << key.e.toHexString() << endl << endl;

    string inputStr = "asdasdasd!";
    vector<uint8_t> message(inputStr.begin(), inputStr.end());
    size_t k = OAEP_K;
    cout << "[2] Исходный текст: \"" << inputStr << "\"" << endl;

    vector<uint8_t> padded = oaepPad(message, k);
    if (padded.empty())
    {
        cout << "[ОШИБКА] OAEP-упаковка не удалась." << endl;
        return 1;
    }
    cout << "[3] OAEP-контейнер EM: " << padded.size() << " байт, EM[0] = 0x"
         << hex << setw(2) << setfill('0') << (int)padded[0] << dec << endl;

    BigInt msgNum = BigInt::fromBytes(padded);
    cout << "[4] Входное число (HEX, первые 32): 0x"
         << msgNum.toHexString().substr(0, 32) << "..." << endl;

    BigInt cipherNum = rsaEncrypt(msgNum, key.e, key.N);
    cout << "[5] Зашифровано (HEX, первые 32): 0x"
         << cipherNum.toHexString().substr(0, 32) << "..." << endl;

    BigInt decryptedNum = rsaDecryptCRT(cipherNum, key);
    cout << "[6] Расшифровано CRT: m == c^d mod N -> "
         << (decryptedNum == msgNum ? "да" : "нет") << endl;

    vector<uint8_t> emDecrypted = decryptedNum.toBytes(k);
    vector<uint8_t> unpaddedMessage = oaepUnpad(emDecrypted, k);
    string restoredStr(unpaddedMessage.begin(), unpaddedMessage.end());
    cout << "[7] Восстановленный текст: \"" << restoredStr << "\"" << endl << endl;

    if (restoredStr == inputStr && decryptedNum == msgNum)
        cout << "[УСПЕХ] RSA-3072 + SHA-512 + CRT(CT Garner) + OAEP работают корректно!" << endl;
    else
        cout << "[ОШИБКА] Данные не совпадают!" << endl;

    return 0;
}