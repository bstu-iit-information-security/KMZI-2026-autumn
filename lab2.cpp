#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstdint>
#include <chrono>
#include <random>
#include <cstring>
#include <windows.h>

using namespace std;

#define SHA384_DIGEST_LENGTH 48

namespace sha384_detail
{
    static const uint64_t K[80] = {
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

    static inline uint64_t rotr(uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }

    struct Ctx
    {
        uint64_t h[8];
        uint8_t  buffer[128];
        uint64_t length;
        size_t   bufferLen;
    };

    static void init(Ctx& c)
    {
        static const uint64_t IV[8] = {
            0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
            0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
        };
        for (int i = 0; i < 8; ++i) c.h[i] = IV[i];
        c.length = 0;
        c.bufferLen = 0;
    }

    static void processBlock(Ctx& c, const uint8_t* block)
    {
        uint64_t w[80];
        for (int i = 0; i < 16; ++i)
        {
            uint64_t v = 0;
            for (int j = 0; j < 8; ++j) v = (v << 8) | block[i * 8 + j];
            w[i] = v;
        }
        for (int i = 16; i < 80; ++i)
        {
            uint64_t s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
            uint64_t s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint64_t a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3];
        uint64_t e = c.h[4], f = c.h[5], g = c.h[6], h = c.h[7];

        for (int i = 0; i < 80; ++i)
        {
            uint64_t S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t t1 = h + S1 + ch + K[i] + w[i];
            uint64_t S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
            uint64_t maj = (a & b) ^ (a & cc) ^ (b & cc);
            uint64_t t2 = S0 + maj;

            h = g; g = f; f = e; e = d + t1;
            d = cc; cc = b; b = a; a = t1 + t2;
        }

        c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d;
        c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += h;
    }

    static void update(Ctx& c, const uint8_t* data, size_t len)
    {
        c.length += len;
        while (len > 0)
        {
            size_t take = 128 - c.bufferLen;
            if (take > len) take = len;
            memcpy(c.buffer + c.bufferLen, data, take);
            c.bufferLen += take;
            data += take;
            len -= take;
            if (c.bufferLen == 128)
            {
                processBlock(c, c.buffer);
                c.bufferLen = 0;
            }
        }
    }

    static void finalize(Ctx& c, uint8_t* out)
    {
        uint64_t bitLen = c.length * 8;

        uint8_t pad = 0x80;
        update(c, &pad, 1);

        uint8_t zero = 0;
        while (c.bufferLen != 112) update(c, &zero, 1);

        uint8_t lenBytes[16];
        for (int i = 0; i < 8; ++i) lenBytes[i] = 0;
        for (int i = 0; i < 8; ++i)
            lenBytes[8 + i] = static_cast<uint8_t>((bitLen >> (56 - 8 * i)) & 0xFF);
        update(c, lenBytes, 16);

        for (int i = 0; i < 6; ++i)
            for (int j = 0; j < 8; ++j)
                out[i * 8 + j] = static_cast<uint8_t>((c.h[i] >> (56 - 8 * j)) & 0xFF);
    }
}

static void SHA384(const uint8_t* data, size_t len, uint8_t* out)
{
    sha384_detail::Ctx c;
    sha384_detail::init(c);
    sha384_detail::update(c, data, len);
    sha384_detail::finalize(c, out);
}

const size_t HASH_LEN = SHA384_DIGEST_LENGTH;

vector<uint8_t> hexToBytes(const string& hex)
{
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
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
        if (s.length() % 8 != 0) s = string(8 - s.length() % 8, '0') + s;
        for (int i = (int)s.length() - 8; i >= 0; i -= 8)
        {
            uint32_t limb = static_cast<uint32_t>(stoul(s.substr(i, 8), nullptr, 16));
            digits.push_back(limb);
        }
        trim();
    }

    void trim()
    {
        while (digits.size() > 1 && digits.back() == 0) digits.pop_back();
    }

    bool isEven() const { return (digits[0] & 1) == 0; }

    size_t bitLength() const
    {
        if (digits.size() == 1 && digits[0] == 0) return 0;
        size_t bits = (digits.size() - 1) * 32;
        uint32_t top = digits.back();
        while (top > 0)
        {
            bits++;
            top >>= 1;
        }
        return bits;
    }

    bool operator==(const BigInt& other) const { return digits == other.digits; }
    bool operator!=(const BigInt& other) const { return !(*this == other); }

    bool operator<(const BigInt& other) const
    {
        if (digits.size() != other.digits.size()) return digits.size() < other.digits.size();
        for (int i = (int)digits.size() - 1; i >= 0; --i)
        {
            if (digits[i] != other.digits[i]) return digits[i] < other.digits[i];
        }
        return false;
    }

    bool operator>(const BigInt& other) const
    {
        if (digits.size() != other.digits.size()) return digits.size() > other.digits.size();
        for (int i = (int)digits.size() - 1; i >= 0; --i)
        {
            if (digits[i] != other.digits[i]) return digits[i] > other.digits[i];
        }
        return false;
    }

    bool operator>=(const BigInt& other) const { return !(*this < other); }
    bool operator<=(const BigInt& other) const { return !(*this > other); }

    BigInt operator+(const BigInt& other) const
    {
        BigInt res;
        res.digits.clear();
        uint64_t carry = 0;
        size_t maxSize = max(digits.size(), other.digits.size());

        for (size_t i = 0; i < maxSize || carry; ++i)
        {
            uint64_t sum = carry;
            if (i < digits.size()) sum += digits[i];
            if (i < other.digits.size()) sum += other.digits[i];
            res.digits.push_back(static_cast<uint32_t>(sum & 0xFFFFFFFF));
            carry = sum >> 32;
        }
        res.trim();
        return res;
    }

    BigInt operator-(const BigInt& other) const
    {
        if (*this < other) return BigInt(0);
        BigInt res;
        res.digits.clear();
        int64_t borrow = 0;
        for (size_t i = 0; i < digits.size(); ++i)
        {
            int64_t diff = static_cast<int64_t>(digits[i]) - borrow;
            if (i < other.digits.size()) diff -= other.digits[i];
            if (diff < 0)
            {
                diff += 0x100000000LL;
                borrow = 1;
            }
            else borrow = 0;
            res.digits.push_back(static_cast<uint32_t>(diff));
        }
        res.trim();
        return res;
    }

    BigInt operator*(const BigInt& other) const
    {
        BigInt res;
        res.digits.assign(digits.size() + other.digits.size(), 0);
        for (size_t i = 0; i < digits.size(); ++i)
        {
            uint64_t carry = 0;
            for (size_t j = 0; j < other.digits.size() || carry; ++j)
            {
                uint64_t cur = res.digits[i + j] +
                    static_cast<uint64_t>(digits[i]) * (j < other.digits.size() ? other.digits[j] : 0) + carry;
                res.digits[i + j] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
                carry = cur >> 32;
            }
        }
        res.trim();
        return res;
    }

    BigInt shiftLeft1() const
    {
        BigInt res;
        res.digits.clear();
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

    // Длинное деление с основанием 2^32 (алгоритм D из Кнута).
    // Работает лимб за лимбом, а не бит за битом, поэтому на порядки
    // быстрее и делает модульное возведение в степень пригодным.
    pair<BigInt, BigInt> divmod(const BigInt& divisor) const
    {
        if (divisor == BigInt(0)) return { BigInt(0), BigInt(0) };
        if (*this < divisor) return { BigInt(0), *this };

        // Быстрый путь: делитель укладывается в один лимб
        if (divisor.digits.size() == 1)
        {
            uint64_t d = divisor.digits[0];
            BigInt q;
            q.digits.assign(digits.size(), 0);
            uint64_t rem = 0;
            for (int i = static_cast<int>(digits.size()) - 1; i >= 0; --i)
            {
                uint64_t cur = (rem << 32) | digits[i];
                q.digits[i] = static_cast<uint32_t>(cur / d);
                rem = cur % d;
            }
            q.trim();
            return { q, BigInt(rem) };
        }

        const uint64_t B = 0x100000000ULL;
        size_t n = divisor.digits.size();
        size_t m = digits.size() - n;

        // Нормализация: сдвиг влево так, чтобы старший лимб делителя был >= B/2
        uint32_t shift = 0;
        for (uint32_t t = divisor.digits.back(); (t & 0x80000000u) == 0; t <<= 1) shift++;

        vector<uint32_t> vn(n);
        vector<uint32_t> un(digits.size() + 1, 0);

        if (shift == 0)
        {
            for (size_t i = 0; i < n; ++i) vn[i] = divisor.digits[i];
            for (size_t i = 0; i < digits.size(); ++i) un[i] = digits[i];
        }
        else
        {
            for (size_t i = 0; i < n; ++i)
            {
                uint32_t lo = (i > 0) ? divisor.digits[i - 1] : 0;
                vn[i] = (divisor.digits[i] << shift) | (lo >> (32 - shift));
            }
            for (size_t i = 0; i < digits.size(); ++i)
            {
                uint32_t lo = (i > 0) ? digits[i - 1] : 0;
                un[i] = (digits[i] << shift) | (lo >> (32 - shift));
            }
            un[digits.size()] = digits.back() >> (32 - shift);
        }

        vector<uint32_t> qd(m + 1, 0);

        for (int j = static_cast<int>(m); j >= 0; --j)
        {
            uint64_t numerator = (static_cast<uint64_t>(un[j + n]) << 32) | un[j + n - 1];
            uint64_t qhat = numerator / vn[n - 1];
            uint64_t rhat = numerator - qhat * vn[n - 1];

            while (qhat >= B ||
                   qhat * vn[n - 2] > ((rhat << 32) | un[j + n - 2]))
            {
                qhat--;
                rhat += vn[n - 1];
                if (rhat >= B) break;
            }

            int64_t k = 0;
            for (size_t i = 0; i < n; ++i)
            {
                uint64_t p = qhat * vn[i];
                int64_t t = static_cast<int64_t>(un[i + j]) - k
                          - static_cast<int64_t>(static_cast<uint32_t>(p & 0xFFFFFFFF));
                un[i + j] = static_cast<uint32_t>(t);
                k = static_cast<int64_t>(p >> 32) - (t >> 32);
            }
            int64_t t = static_cast<int64_t>(un[j + n]) - k;
            un[j + n] = static_cast<uint32_t>(t);

            qd[j] = static_cast<uint32_t>(qhat);
            if (t < 0) // qhat оказался на 1 больше — добавляем делитель назад
            {
                qd[j]--;
                k = 0;
                for (size_t i = 0; i < n; ++i)
                {
                    int64_t s = static_cast<int64_t>(un[i + j]) + vn[i] + k;
                    un[i + j] = static_cast<uint32_t>(s);
                    k = s >> 32;
                }
                un[j + n] += static_cast<uint32_t>(k);
            }
        }

        // Денормализация остатка (сдвиг вправо)
        vector<uint32_t> rd(n);
        if (shift == 0)
        {
            for (size_t i = 0; i < n; ++i) rd[i] = un[i];
        }
        else
        {
            for (size_t i = 0; i < n; ++i)
            {
                uint32_t lo = un[i] >> shift;
                uint32_t hi = (i + 1 < n) ? (un[i + 1] << (32 - shift)) : 0;
                rd[i] = lo | hi;
            }
        }

        BigInt q, r;
        q.digits = qd; q.trim();
        r.digits = rd; r.trim();
        return { q, r };
    }

    BigInt operator/(const BigInt& other) const { return divmod(other).first; }
    BigInt operator%(const BigInt& other) const { return divmod(other).second; }

    string toHexString() const
    {
        stringstream ss;
        ss << hex << uppercase;
        ss << digits.back();
        for (int i = (int)digits.size() - 2; i >= 0; --i)
        {
            ss << setfill('0') << setw(8) << digits[i];
        }
        return ss.str();
    }
};

BigInt modPow(BigInt base, BigInt exp, BigInt mod)
{
    BigInt result = 1;
    base = base % mod;
    while (exp != BigInt(0))
    {
        if (exp.digits[0] & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp = exp.shiftRight1();
    }
    return result;
}

BigInt modInverseBEEACT(BigInt a, BigInt m, int bitLen)
{
    BigInt u = a, v = m;
    BigInt x1 = 1, x2 = 0;
    BigInt zero = 0;
    
    int max_iters = 2 * bitLen; 
    
    for (int i = 0; i < max_iters; ++i)
    {
        if (u > zero && v > zero)
        {
            if (u.isEven())
            {
                u = u.shiftRight1();
                if (x1.isEven()) x1 = x1.shiftRight1();
                else x1 = (x1 + m).shiftRight1();
            }
            else if (v.isEven())
            {
                v = v.shiftRight1();
                if (x2.isEven()) x2 = x2.shiftRight1();
                else x2 = (x2 + m).shiftRight1();
            }
            else if (u >= v)
            {
                u = u - v;
                if (x1 >= x2) x1 = x1 - x2;
                else x1 = x1 + m - x2;
            }
            else
            {
                v = v - u;
                if (x2 >= x1) x2 = x2 - x1;
                else x2 = x2 + m - x1;
            }
        }
    }
    return (u == zero) ? x2 : x1;
}

vector<uint8_t> getSha384(const vector<uint8_t>& data)
{
    vector<uint8_t> hash(SHA384_DIGEST_LENGTH);
    SHA384(data.data(), data.size(), hash.data());
    return hash;
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

        vector<uint8_t> hash = getSha384(seedData);
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
    while (d.isEven())
    {
        d = d.shiftRight1();
        s++;
    }

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
            if (x == n - BigInt(1))
            {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

BigInt generateLargePrime(size_t bitLen)
{
    while (true)
    {
        BigInt candidate = generateRandomBigInt(bitLen);
        if (isPrimeMillerRabin(candidate)) return candidate;
    }
}

vector<uint8_t> mgf1(const vector<uint8_t>& seed, size_t length)
{
    vector<uint8_t> mask;
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

        vector<uint8_t> hash = getSha384(temp);
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

    vector<uint8_t> lHash = getSha384({});
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

vector<uint8_t> oaepUnpad(const vector<uint8_t>& em, size_t k)
{
    if (em.size() < 2 * HASH_LEN + 2) return {};

    vector<uint8_t> maskedSeed(em.begin() + 1, em.begin() + 1 + HASH_LEN);
    vector<uint8_t> maskedDB(em.begin() + 1 + HASH_LEN, em.end());

    vector<uint8_t> seedMask = mgf1(maskedDB, HASH_LEN);
    vector<uint8_t> seed(HASH_LEN);
    for (size_t i = 0; i < HASH_LEN; ++i) seed[i] = maskedSeed[i] ^ seedMask[i];

    vector<uint8_t> dbMask = mgf1(seed, k - HASH_LEN - 1);
    vector<uint8_t> db(maskedDB.size());
    for (size_t i = 0; i < maskedDB.size(); ++i) db[i] = maskedDB[i] ^ dbMask[i];

    size_t msgStart = HASH_LEN;
    while (msgStart < db.size() && db[msgStart] != 0x01) msgStart++;
    msgStart++;

    if (msgStart > db.size()) return {};
    return vector<uint8_t>(db.begin() + msgStart, db.end());
}

struct RSAKey
{
    BigInt N, e, d, p, q, dp, dq, qinv;
};

RSAKey generateKeys(size_t keyBitLen = 4096)
{
    RSAKey key;
    size_t primeBits = keyBitLen / 2;

    cout << "   [!] Generating p (" << primeBits << " bits)..." << endl;
    key.p = generateLargePrime(primeBits);

    cout << "   [!] Generating q (" << primeBits << " bits)..." << endl;
    do {
        key.q = generateLargePrime(primeBits);
    } while (key.p == key.q);

    key.N = key.p * key.q;
    BigInt phi = (key.p - BigInt(1)) * (key.q - BigInt(1));
    key.e = BigInt(65537);

    while (phi % key.e == BigInt(0)) key.e = key.e + BigInt(2);

    key.d = modInverseBEEACT(key.e, phi, primeBits * 2);
    key.dp = key.d % (key.p - BigInt(1));
    key.dq = key.d % (key.q - BigInt(1));
    
    key.qinv = modInverseBEEACT(key.q, key.p, primeBits);

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
    setlocale(LC_ALL, "Rus");
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    cout << "RSA (4096 bit) + SHA-384 + CT BEEA..." << endl;
    RSAKey key = generateKeys(4096);

    cout << "[+] Keys generated successfully." << endl;
    cout << "   Modulus N (HEX):   0x" << key.N.toHexString() << endl;
    cout << "   Exponent e:        0x" << key.e.toHexString() << endl;
    cout << "   CRT qinv (CT):     0x" << key.qinv.toHexString() << endl << endl;

    string inputStr = "Hello, Constant-Time RSA!";
    vector<uint8_t> message(inputStr.begin(), inputStr.end());
    size_t k = 512;
    
    cout << "[1] Source text: \"" << inputStr << "\"" << endl;
    vector<uint8_t> padded = oaepPad(message, k);

    BigInt msgNum = 0;
    for (size_t i = 0; i < min(padded.size(), static_cast<size_t>(k)); ++i)
    {
        msgNum = msgNum * BigInt(256) + BigInt(padded[i]);
    }

    BigInt cipherNum = rsaEncrypt(msgNum, key.e, key.N);
    cout << "[2] Ciphertext (HEX): 0x" << cipherNum.toHexString().substr(0, 32) << "...(truncated)" << endl;

    BigInt decryptedNum = rsaDecryptCRT(cipherNum, key);
    
    vector<uint8_t> decryptedPadded;
    BigInt temp = decryptedNum;
    while (temp > BigInt(0))
    {
        decryptedPadded.insert(decryptedPadded.begin(), static_cast<uint8_t>((temp % BigInt(256)).digits[0]));
        temp = temp / BigInt(256);
    }
    
    while(decryptedPadded.size() < k) decryptedPadded.insert(decryptedPadded.begin(), 0);

    vector<uint8_t> unpaddedMessage = oaepUnpad(decryptedPadded, k);
    string restoredStr(unpaddedMessage.begin(), unpaddedMessage.end());
    cout << "[3] Restored text from OAEP: \"" << restoredStr << "\"" << endl << endl;

    if (restoredStr == inputStr) cout << "[SUCCESS] Encryption and decryption work correctly!" << endl;
    else cout << "[ERROR] Data mismatch!" << endl;

    return 0;
}