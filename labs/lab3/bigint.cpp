#include "bigint.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>

BigInt::BigInt(uint64_t v) {
    if (v != 0) {
        words[0] = (uint32_t)(v & 0xFFFFFFFF);
        words[1] = (uint32_t)(v >> 32);
        size = (words[1] != 0) ? 2 : 1;
    }
}

BigInt::BigInt(const std::string& hex_str) {
    std::string s = hex_str;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s = s.substr(2);
    if (s.empty()) return;

    size_t n = s.size();
    size_t word_idx = 0;
    for (size_t i = 0; i < n && word_idx < MAX_WORDS; i += 8, ++word_idx) {
        size_t end = n - i;
        size_t start = (end >= 8) ? end - 8 : 0;
        size_t len = end - start;
        std::string chunk = s.substr(start, len);
        words[word_idx] = (uint32_t)std::stoul(chunk, nullptr, 16);
    }
    size = word_idx;
    trim();
}

BigInt& BigInt::operator=(uint64_t v) {
    *this = BigInt(v);
    return *this;
}

void BigInt::trim() {
    while (size > 0 && words[size - 1] == 0) --size;
    if (size == 0) negative = false;
}

size_t BigInt::bit_length() const {
    if (size == 0) return 0;
    size_t bits = (size - 1) * 32;
    uint32_t top = words[size - 1];
    while (top) { ++bits; top >>= 1; }
    return bits;
}

bool BigInt::bit(size_t i) const {
    size_t w = i / 32;
    size_t b = i % 32;
    if (w >= size) return false;
    return (words[w] >> b) & 1;
}

uint64_t BigInt::to_uint64() const {
    uint64_t v = 0;
    if (size > 0) v |= (uint64_t)words[0];
    if (size > 1) v |= ((uint64_t)words[1]) << 32;
    return v;
}

std::string BigInt::to_hex() const {
    if (size == 0) return "0";
    std::stringstream ss;
    ss << std::hex << words[size - 1];
    for (size_t i = size - 1; i-- > 0; )
        ss << std::setw(8) << std::setfill('0') << words[i];
    return ss.str();
}

std::string to_hex(const BigInt& value) { return value.to_hex(); }

void BigInt::cmov(const BigInt& other, bool condition) {
    uint32_t mask = 0 - static_cast<uint32_t>(condition);
    uint32_t inv_mask = ~mask;
    for (size_t i = 0; i < MAX_WORDS; ++i) {
        words[i] = (words[i] & inv_mask) | (other.words[i] & mask);
    }
    size = (size & inv_mask) | (other.size & mask);
    negative = (negative && !condition) || (other.negative && condition);
}

BigInt BigInt::constant_time_select(bool condition, const BigInt& true_val, const BigInt& false_val) {
    BigInt result = false_val;
    result.cmov(true_val, condition);
    return result;
}

bool BigInt::operator==(const BigInt& o) const {
    if (negative != o.negative) return false;
    if (size != o.size) return false;
    for (size_t i = 0; i < size; ++i)
        if (words[i] != o.words[i]) return false;
    return true;
}

bool BigInt::operator<(const BigInt& o) const {
    if (negative != o.negative) return negative;
    if (size != o.size) {
        bool r = size < o.size;
        return negative ? !r : r;
    }
    for (size_t i = size; i-- > 0; )
        if (words[i] != o.words[i]) {
            bool r = words[i] < o.words[i];
            return negative ? !r : r;
        }
    return false;
}

BigInt BigInt::operator+(const BigInt& o) const {
    if (negative != o.negative) {
        BigInt tmp = o;
        tmp.negative = !tmp.negative;
        return *this - tmp;
    }
    BigInt r;
    r.negative = negative;
    size_t n = std::max(size, o.size);
    uint64_t carry = 0;
    for (size_t i = 0; i < n; ++i) {
        uint64_t a = (i < size) ? words[i] : 0;
        uint64_t b = (i < o.size) ? o.words[i] : 0;
        uint64_t s = a + b + carry;
        r.words[i] = (uint32_t)(s & 0xFFFFFFFF);
        carry = s >> 32;
    }
    if (carry && n < MAX_WORDS) r.words[n++] = (uint32_t)carry;
    r.size = n;
    r.trim();
    return r;
}

BigInt BigInt::operator-(const BigInt& o) const {
    if (negative != o.negative) {
        BigInt tmp = o;
        tmp.negative = !tmp.negative;
        return *this + tmp;
    }
    bool this_less = false;
    if (size != o.size) this_less = size < o.size;
    else for (size_t i = size; i-- > 0; )
        if (words[i] != o.words[i]) { this_less = words[i] < o.words[i]; break; }

    if (this_less) {
        BigInt r = o - *this;
        r.negative = !negative;
        return r;
    }
    BigInt r;
    r.negative = negative;
    r.size = size;
    int64_t borrow = 0;
    for (size_t i = 0; i < size; ++i) {
        int64_t a = words[i];
        int64_t b = (i < o.size) ? o.words[i] : 0;
        int64_t d = a - b - borrow;
        if (d < 0) { d += ((int64_t)1 << 32); borrow = 1; } else borrow = 0;
        r.words[i] = (uint32_t)d;
    }
    r.trim();
    return r;
}

BigInt BigInt::operator*(const BigInt& o) const {
    BigInt r;
    if (is_zero() || o.is_zero()) return r;
    r.negative = negative != o.negative;
    std::array<uint32_t, MAX_WORDS> tmp{};
    for (size_t i = 0; i < size; ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < o.size && i + j < MAX_WORDS; ++j) {
            uint64_t cur = (uint64_t)words[i] * o.words[j] + tmp[i + j] + carry;
            tmp[i + j] = (uint32_t)(cur & 0xFFFFFFFF);
            carry = cur >> 32;
        }
        if (i + o.size < MAX_WORDS)
            tmp[i + o.size] += (uint32_t)carry;
    }
    r.words = tmp;
    r.size = std::min(size + o.size, MAX_WORDS);
    r.trim();
    return r;
}

BigInt BigInt::operator/(const BigInt& o) const {
    if (o.is_zero()) throw std::runtime_error("div by zero");
    if (*this < o) return BigInt();

    BigInt quotient;
    BigInt remainder;
    size_t bits = bit_length();
    for (size_t i = bits; i-- > 0; ) {
        remainder = remainder << 1;
        if (bit(i)) remainder.words[0] |= 1;
        remainder.trim();
        if (remainder >= o) {
            remainder = remainder - o;
            quotient.words[i / 32] |= (1u << (i % 32));
            if (quotient.size <= i / 32) quotient.size = i / 32 + 1;
        }
    }
    quotient.trim();
    return quotient;
}

BigInt BigInt::operator%(const BigInt& o) const {
    if (o.is_zero()) throw std::runtime_error("mod by zero");
    if (*this < o) return *this;
    BigInt remainder;
    size_t bits = bit_length();
    for (size_t i = bits; i-- > 0; ) {
        remainder = remainder << 1;
        if (bit(i)) remainder.words[0] |= 1;
        remainder.trim();
        if (remainder >= o) remainder = remainder - o;
    }
    return remainder;
}

BigInt BigInt::operator&(const BigInt& o) const {
    BigInt r;
    r.size = std::min(size, o.size);
    for (size_t i = 0; i < r.size; ++i) r.words[i] = words[i] & o.words[i];
    r.trim();
    return r;
}

BigInt BigInt::operator|(const BigInt& o) const {
    BigInt r;
    r.size = std::max(size, o.size);
    for (size_t i = 0; i < r.size; ++i) {
        uint32_t a = (i < size)   ? words[i]   : 0;
        uint32_t b = (i < o.size) ? o.words[i] : 0;
        r.words[i] = a | b;
    }
    r.trim();
    return r;
}

BigInt BigInt::operator^(const BigInt& o) const {
    BigInt r;
    r.size = std::max(size, o.size);
    for (size_t i = 0; i < r.size; ++i) {
        uint32_t a = (i < size) ? words[i] : 0;
        uint32_t b = (i < o.size) ? o.words[i] : 0;
        r.words[i] = a ^ b;
    }
    r.trim();
    return r;
}

BigInt BigInt::operator>>(size_t shift) const {
    BigInt r;
    size_t ws = shift / 32, bs = shift % 32;
    if (ws >= size) return r;
    r.size = size - ws;
    for (size_t i = 0; i < r.size; ++i) {
        uint32_t lo = words[i + ws] >> bs;
        uint32_t hi = (i + ws + 1 < size && bs)
                    ? (words[i + ws + 1] << (32 - bs)) : 0;
        r.words[i] = lo | hi;
    }
    r.trim();
    return r;
}

BigInt BigInt::operator<<(size_t shift) const {
    BigInt r;
    if (is_zero()) return r;
    size_t ws = shift / 32, bs = shift % 32;
    if (size + ws + 1 > MAX_WORDS) throw std::runtime_error("overflow <<");
    r.size = size + ws + 1;
    for (size_t i = 0; i < size; ++i) {
        uint64_t v = (uint64_t)words[i] << bs;
        r.words[i + ws] |= (uint32_t)(v & 0xFFFFFFFF);
        r.words[i + ws + 1] |= (uint32_t)(v >> 32);
    }
    r.trim();
    return r;
}

BigInt mod_add(const BigInt& a, const BigInt& b, const BigInt& p) {
    BigInt r = a + b;
    if (r >= p) r = r - p;
    return r;
}

BigInt mod_sub(const BigInt& a, const BigInt& b, const BigInt& p) {
    BigInt r = a - b;
    if (r.negative || r >= p) r = r + p;
    return r;
}

BigInt mod_mul(const BigInt& a, const BigInt& b, const BigInt& p) {
    return (a * b) % p;
}

BigInt mod_pow(const BigInt& base, const BigInt& exp, const BigInt& mod) {
    BigInt result(1);
    BigInt b = base % mod;
    size_t bits = exp.bit_length();
    for (size_t i = bits; i-- > 0; ) {
        result = mod_mul(result, result, mod);
        BigInt product = mod_mul(result, b, mod);
        result.cmov(product, exp.bit(i));
    }
    return result;
}

BigInt mod_inverse(const BigInt& a, const BigInt& p) {
    BigInt exp = p - BigInt(2);
    return mod_pow(a, exp, p);
}

BigInt random_scalar(const BigInt& q) {
    static uint64_t seed = 0xDEADBEEFCAFEBABEULL;
    seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
    uint64_t r1 = seed;
    seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
    uint64_t r2 = seed;
    BigInt r(r1);
    r = (r << 64) | BigInt(r2);
    return (r % (q - BigInt(1))) + BigInt(1);
}
