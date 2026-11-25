#include "rsa_math.hpp"

#include <windows.h>
#include <wincrypt.h>

#include <cstring>

namespace {

uint32_t neg_inverse(uint32_t odd) {
    uint32_t inverse = 1;
    inverse *= 2u - odd * inverse;
    inverse *= 2u - odd * inverse;
    inverse *= 2u - odd * inverse;
    inverse *= 2u - odd * inverse;
    inverse *= 2u - odd * inverse;
    return 0u - inverse;
}

void montgomery_mul(uint32_t* result, const uint32_t* left, const uint32_t* right, const uint32_t* modulus,
                    uint32_t n0, int limbs) {
    uint32_t acc[Bn::kLimbs + 2] = {};
    for (int i = 0; i < limbs; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < limbs; ++j) {
            const uint64_t sum = static_cast<uint64_t>(acc[j]) + static_cast<uint64_t>(left[j]) * right[i] + carry;
            acc[j] = static_cast<uint32_t>(sum);
            carry = sum >> 32;
        }
        uint64_t top = static_cast<uint64_t>(acc[limbs]) + carry;
        acc[limbs] = static_cast<uint32_t>(top);
        acc[limbs + 1] = static_cast<uint32_t>(top >> 32);

        const uint32_t m = acc[0] * n0;
        carry = static_cast<uint64_t>(acc[0]) + static_cast<uint64_t>(m) * modulus[0];
        carry >>= 32;
        for (int j = 1; j < limbs; ++j) {
            const uint64_t sum = static_cast<uint64_t>(acc[j]) + static_cast<uint64_t>(m) * modulus[j] + carry;
            acc[j - 1] = static_cast<uint32_t>(sum);
            carry = sum >> 32;
        }
        top = static_cast<uint64_t>(acc[limbs]) + carry;
        acc[limbs - 1] = static_cast<uint32_t>(top);
        acc[limbs] = acc[limbs + 1] + static_cast<uint32_t>(top >> 32);
        acc[limbs + 1] = 0;
    }

    auto not_smaller = [&]() {
        if (acc[limbs] != 0) {
            return true;
        }
        for (int i = limbs - 1; i >= 0; --i) {
            if (acc[i] != modulus[i]) {
                return acc[i] > modulus[i];
            }
        }
        return true;
    };
    for (int pass = 0; pass < 2 && not_smaller(); ++pass) {
        uint64_t borrow = 0;
        for (int i = 0; i < limbs; ++i) {
            const uint32_t current = acc[i];
            const uint64_t need = static_cast<uint64_t>(modulus[i]) + borrow;
            acc[i] = static_cast<uint32_t>(static_cast<uint64_t>(current) - need);
            borrow = static_cast<uint64_t>(current) < need ? 1 : 0;
        }
        acc[limbs] -= static_cast<uint32_t>(borrow);
    }
    std::memcpy(result, acc, static_cast<std::size_t>(limbs) * sizeof(uint32_t));
}

uint32_t limbs_equal(const uint32_t* left, const uint32_t* right, int limbs) {
    uint32_t diff = 0;
    for (int i = 0; i < limbs; ++i) {
        diff |= left[i] ^ right[i];
    }
    return static_cast<uint32_t>(diff == 0);
}

const uint32_t* small_primes(int& count) {
    static uint32_t primes[1300];
    static int stored = 0;
    if (stored == 0) {
        static constexpr int kLimit = 10000;
        bool composite[kLimit] = {};
        for (int i = 2; i * i < kLimit; ++i) {
            if (!composite[i]) {
                for (int j = i * i; j < kLimit; j += i) {
                    composite[j] = true;
                }
            }
        }
        for (int i = 2; i < kLimit && stored < static_cast<int>(sizeof(primes) / sizeof(primes[0])); ++i) {
            if (!composite[i]) {
                primes[stored++] = static_cast<uint32_t>(i);
            }
        }
    }
    count = stored;
    return primes;
}

}

void Bn::clear() {
    std::memset(limb_, 0, sizeof(limb_));
    size_ = 0;
    negative_ = false;
}

void Bn::trim() {
    while (size_ > 0 && limb_[size_ - 1] == 0) {
        --size_;
    }
    if (size_ == 0) {
        negative_ = false;
    }
}

void Bn::set_u64(uint64_t value) {
    clear();
    if (value == 0) {
        return;
    }
    limb_[0] = static_cast<uint32_t>(value);
    limb_[1] = static_cast<uint32_t>(value >> 32);
    size_ = limb_[1] == 0 ? 1 : 2;
}

void Bn::set_bytes_be(const uint8_t* data, int length) {
    clear();
    for (int i = 0; i < length; ++i) {
        const int shift = (length - 1 - i) * 8;
        limb_[shift / 32] |= static_cast<uint32_t>(data[i]) << (shift % 32);
    }
    size_ = (length + 3) / 4;
    trim();
}

void Bn::to_bytes_be(uint8_t* data, int length) const {
    std::memset(data, 0, static_cast<std::size_t>(length));
    for (int i = 0; i < length; ++i) {
        const int shift = (length - 1 - i) * 8;
        const int limb = shift / 32;
        if (limb < size_) {
            data[i] = static_cast<uint8_t>(limb_[limb] >> (shift % 32));
        }
    }
}

int Bn::bit_length() const {
    if (size_ == 0) {
        return 0;
    }
    return (size_ - 1) * 32 + (32 - __builtin_clz(limb_[size_ - 1]));
}

bool Bn::bit(int index) const {
    const int limb = index / 32;
    if (index < 0 || limb >= size_) {
        return false;
    }
    return ((limb_[limb] >> (index % 32)) & 1u) != 0;
}

void Bn::set_bit(int index) {
    const int limb = index / 32;
    while (size_ <= limb) {
        limb_[size_++] = 0;
    }
    limb_[limb] |= 1u << (index % 32);
}

bool Bn::is_zero() const { return size_ == 0; }

bool Bn::is_odd() const { return size_ > 0 && (limb_[0] & 1u) != 0; }

bool Bn::fits_u64() const { return size_ <= 2; }

uint64_t Bn::as_u64() const {
    uint64_t value = size_ > 0 ? limb_[0] : 0;
    if (size_ > 1) {
        value |= static_cast<uint64_t>(limb_[1]) << 32;
    }
    return value;
}

int Bn::cmp(const Bn& other) const {
    if (negative_ != other.negative_) {
        if (is_zero() && other.is_zero()) {
            return 0;
        }
        return negative_ ? -1 : 1;
    }
    const int sign = negative_ ? -1 : 1;
    if (size_ != other.size_) {
        return size_ > other.size_ ? sign : -sign;
    }
    for (int i = size_ - 1; i >= 0; --i) {
        if (limb_[i] != other.limb_[i]) {
            return limb_[i] > other.limb_[i] ? sign : -sign;
        }
    }
    return 0;
}

void Bn::shift_left_one() {
    uint32_t carry = 0;
    for (int i = 0; i < size_; ++i) {
        const uint32_t next = limb_[i] >> 31;
        limb_[i] = (limb_[i] << 1) | carry;
        carry = next;
    }
    if (carry != 0 && size_ < kLimbs) {
        limb_[size_++] = carry;
    }
}

void Bn::shift_right(int bits) {
    if (bits <= 0 || size_ == 0) {
        return;
    }
    const int limb_shift = bits / 32;
    const int bit_shift = bits % 32;
    if (limb_shift >= size_) {
        clear();
        return;
    }
    if (limb_shift > 0) {
        for (int i = 0; i < size_ - limb_shift; ++i) {
            limb_[i] = limb_[i + limb_shift];
        }
        size_ -= limb_shift;
    }
    if (bit_shift > 0) {
        uint32_t carry = 0;
        for (int i = size_ - 1; i >= 0; --i) {
            const uint32_t next = limb_[i] << (32 - bit_shift);
            limb_[i] = (limb_[i] >> bit_shift) | carry;
            carry = next;
        }
    }
    trim();
}

uint32_t Bn::mod_word(uint32_t word) const {
    uint32_t remainder = 0;
    for (int i = size_ - 1; i >= 0; --i) {
        remainder = static_cast<uint32_t>(((static_cast<uint64_t>(remainder) << 32) | limb_[i]) % word);
    }
    return remainder;
}

void Bn::add(Bn& result, const Bn& left, const Bn& right) {
    auto add_abs = [](Bn& out, const Bn& a, const Bn& b) {
        uint64_t carry = 0;
        const int n = a.size_ > b.size_ ? a.size_ : b.size_;
        for (int i = 0; i < n; ++i) {
            uint64_t sum = carry;
            if (i < a.size_) {
                sum += a.limb_[i];
            }
            if (i < b.size_) {
                sum += b.limb_[i];
            }
            out.limb_[i] = static_cast<uint32_t>(sum);
            carry = sum >> 32;
        }
        out.size_ = n;
        if (carry != 0) {
            out.limb_[out.size_++] = static_cast<uint32_t>(carry);
        }
        for (int i = out.size_; i < kLimbs; ++i) {
            out.limb_[i] = 0;
        }
        out.negative_ = false;
    };
    auto sub_abs = [](Bn& out, const Bn& a, const Bn& b) {
        uint64_t borrow = 0;
        for (int i = 0; i < a.size_; ++i) {
            const uint64_t need = (i < b.size_ ? b.limb_[i] : 0) + borrow;
            const uint32_t current = a.limb_[i];
            out.limb_[i] = static_cast<uint32_t>(static_cast<uint64_t>(current) - need);
            borrow = static_cast<uint64_t>(current) < need ? 1 : 0;
        }
        out.size_ = a.size_;
        for (int i = out.size_; i < kLimbs; ++i) {
            out.limb_[i] = 0;
        }
        out.negative_ = false;
        out.trim();
    };

    if (left.negative_ == right.negative_) {
        add_abs(result, left, right);
        result.negative_ = left.negative_ && !result.is_zero();
        return;
    }
    Bn left_abs = left;
    Bn right_abs = right;
    left_abs.negative_ = false;
    right_abs.negative_ = false;
    if (left_abs.cmp(right_abs) >= 0) {
        sub_abs(result, left, right);
        result.negative_ = left.negative_ && !result.is_zero();
    } else {
        sub_abs(result, right, left);
        result.negative_ = right.negative_ && !result.is_zero();
    }
}

void Bn::sub(Bn& result, const Bn& left, const Bn& right) {
    Bn flipped = right;
    if (!flipped.is_zero()) {
        flipped.negative_ = !flipped.negative_;
    }
    add(result, left, flipped);
}

void Bn::mul(Bn& result, const Bn& left, const Bn& right) {
    uint32_t wide[kLimbs] = {};
    for (int i = 0; i < left.size_; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < right.size_; ++j) {
            const uint64_t sum = static_cast<uint64_t>(wide[i + j]) +
                                 static_cast<uint64_t>(left.limb_[i]) * right.limb_[j] + carry;
            wide[i + j] = static_cast<uint32_t>(sum);
            carry = sum >> 32;
        }
        wide[i + right.size_] = static_cast<uint32_t>(static_cast<uint64_t>(wide[i + right.size_]) + carry);
    }
    std::memcpy(result.limb_, wide, sizeof(wide));
    result.size_ = left.size_ + right.size_;
    if (result.size_ > kLimbs) {
        result.size_ = kLimbs;
    }
    result.negative_ = left.negative_ != right.negative_;
    result.trim();
}

void Bn::divmod(Bn& quotient, Bn& remainder, const Bn& left, const Bn& right) {
    quotient.clear();
    remainder.clear();
    if (right.is_zero()) {
        return;
    }
    Bn value = left;
    Bn divisor = right;
    value.negative_ = false;
    divisor.negative_ = false;
    if (value.cmp(divisor) < 0) {
        remainder = value;
        remainder.negative_ = left.negative_ && !remainder.is_zero();
        return;
    }
    const int bits = value.bit_length();
    for (int i = bits - 1; i >= 0; --i) {
        remainder.shift_left_one();
        if (value.bit(i)) {
            remainder.limb_[0] |= 1u;
            if (remainder.size_ == 0) {
                remainder.size_ = 1;
            }
        }
        if (remainder.cmp(divisor) >= 0) {
            Bn next;
            sub(next, remainder, divisor);
            remainder = next;
            quotient.set_bit(i);
        }
    }
    quotient.negative_ = left.negative_ != right.negative_ && !quotient.is_zero();
    remainder.negative_ = left.negative_ && !remainder.is_zero();
}

void Bn::mod(Bn& result, const Bn& value, const Bn& modulus) {
    Bn quotient;
    Bn remainder;
    Bn positive_mod = modulus;
    positive_mod.negative_ = false;
    divmod(quotient, remainder, value, positive_mod);
    if (remainder.negative_) {
        add(result, remainder, positive_mod);
        result.negative_ = false;
        result.trim();
        return;
    }
    result = remainder;
    result.negative_ = false;
}

bool RsaMath::random_bytes(uint8_t* data, int length) {
    HCRYPTPROV provider = 0;
    if (!CryptAcquireContextA(&provider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return false;
    }
    const BOOL ok = CryptGenRandom(provider, static_cast<DWORD>(length), data);
    CryptReleaseContext(provider, 0);
    return ok == TRUE;
}

bool RsaMath::random_below(Bn& result, const Bn& limit) {
    if (limit.cmp(Bn{}) <= 0 && limit.is_zero()) {
        return false;
    }
    const int bytes = (limit.bit_length() + 7) / 8;
    uint8_t buffer[Bn::kLimbs * 4];
    for (int attempt = 0; attempt < 64; ++attempt) {
        if (!random_bytes(buffer, bytes)) {
            return false;
        }
        const int extra = bytes * 8 - limit.bit_length();
        if (extra > 0) {
            buffer[0] &= static_cast<uint8_t>(0xFFu >> extra);
        }
        result.set_bytes_be(buffer, bytes);
        if (result.cmp(limit) < 0) {
            return true;
        }
    }
    return false;
}

bool RsaMath::mod_exp_binary(Bn& result, const Bn& base, const Bn& exponent, const Bn& modulus) {
    if (modulus.is_zero()) {
        return false;
    }
    result.set_u64(1);
    if (exponent.is_zero()) {
        return true;
    }
    Bn reduced;
    Bn::mod(reduced, base, modulus);
    const int bits = exponent.bit_length();
    for (int i = bits - 1; i >= 0; --i) {
        Bn square;
        Bn::mul(square, result, result);
        Bn::mod(result, square, modulus);
        if (exponent.bit(i)) {
            Bn product;
            Bn::mul(product, result, reduced);
            Bn::mod(result, product, modulus);
        }
    }
    return true;
}

void RsaMath::to_montgomery(uint32_t* out, const Bn& value, const Bn& modulus) {
    const int limbs = modulus.size_;
    std::memset(out, 0, static_cast<std::size_t>(limbs) * sizeof(uint32_t));
    Bn reduced;
    Bn::mod(reduced, value, modulus);
    for (int i = reduced.size_ - 1; i >= 0; --i) {
        reduced.limb_[i + limbs] = reduced.limb_[i];
    }
    for (int i = 0; i < limbs; ++i) {
        reduced.limb_[i] = 0;
    }
    reduced.size_ += limbs;
    Bn quotient;
    Bn remainder;
    Bn::divmod(quotient, remainder, reduced, modulus);
    for (int i = 0; i < limbs; ++i) {
        out[i] = i < remainder.size_ ? remainder.limb_[i] : 0;
    }
}

bool RsaMath::mod_exp_montgomery(Bn& result, const Bn& base, const Bn& exponent, const Bn& modulus) {
    const int limbs = modulus.size_;
    const uint32_t n0 = neg_inverse(modulus.limb_[0]);
    uint32_t modulus_limbs[Bn::kLimbs] = {};
    for (int i = 0; i < limbs; ++i) {
        modulus_limbs[i] = modulus.limb_[i];
    }

    Bn one;
    one.set_u64(1);
    uint32_t mont_one[Bn::kLimbs] = {};
    to_montgomery(mont_one, one, modulus);

    uint32_t reduced[Bn::kLimbs] = {};
    to_montgomery(reduced, base, modulus);
    uint32_t acc[Bn::kLimbs] = {};
    std::memcpy(acc, mont_one, sizeof(acc));

    uint32_t tmp[Bn::kLimbs] = {};
    for (int i = exponent.bit_length() - 1; i >= 0; --i) {
        montgomery_mul(tmp, acc, acc, modulus_limbs, n0, limbs);
        std::memcpy(acc, tmp, static_cast<std::size_t>(limbs) * sizeof(uint32_t));
        if (exponent.bit(i)) {
            montgomery_mul(tmp, acc, reduced, modulus_limbs, n0, limbs);
            std::memcpy(acc, tmp, static_cast<std::size_t>(limbs) * sizeof(uint32_t));
        }
    }
    uint32_t normal_one[Bn::kLimbs] = {};
    normal_one[0] = 1;
    montgomery_mul(tmp, acc, normal_one, modulus_limbs, n0, limbs);

    result.clear();
    for (int i = 0; i < limbs; ++i) {
        result.limb_[i] = tmp[i];
    }
    result.size_ = limbs;
    result.trim();
    return true;
}

bool RsaMath::mod_exp(Bn& result, const Bn& base, const Bn& exponent, const Bn& modulus) {
    if (!modulus.is_odd()) {
        return mod_exp_binary(result, base, exponent, modulus);
    }
    if (exponent.is_zero()) {
        result.set_u64(1);
        return true;
    }
    return mod_exp_montgomery(result, base, exponent, modulus);
}

bool RsaMath::extended_gcd(Bn& gcd, Bn& x, Bn& y, const Bn& left, const Bn& right) {
    Bn r0 = left;
    Bn r1 = right;
    r0.negative_ = false;
    r1.negative_ = false;
    Bn s0;
    Bn s1;
    Bn t0;
    Bn t1;
    s0.set_u64(1);
    t1.set_u64(1);
    while (!r1.is_zero()) {
        Bn quotient;
        Bn remainder;
        Bn::divmod(quotient, remainder, r0, r1);
        Bn next_s;
        Bn next_t;
        Bn product;
        Bn::mul(product, quotient, s1);
        Bn::sub(next_s, s0, product);
        Bn::mul(product, quotient, t1);
        Bn::sub(next_t, t0, product);
        r0 = r1;
        r1 = remainder;
        s0 = s1;
        s1 = next_s;
        t0 = t1;
        t1 = next_t;
    }
    gcd = r0;
    x = s0;
    y = t0;
    return true;
}

bool RsaMath::mod_inverse(Bn& result, const Bn& value, const Bn& modulus) {
    Bn gcd;
    Bn x;
    Bn y;
    Bn reduced;
    Bn::mod(reduced, value, modulus);
    if (!extended_gcd(gcd, x, y, reduced, modulus) || gcd.cmp(Bn{}) == 0) {
        return false;
    }
    Bn one;
    one.set_u64(1);
    if (gcd.cmp(one) != 0) {
        return false;
    }
    Bn::mod(result, x, modulus);
    return true;
}

uint32_t RsaMath::witness(const Bn& number, const Bn& base) {
    Bn one;
    one.set_u64(1);
    Bn limit = number;
    Bn::sub(limit, number, one);

    const int width = number.bit_length();
    int valuation = 0;
    uint32_t still = 1;
    for (int i = 0; i < width; ++i) {
        const uint32_t bit = limit.bit(i) ? 1u : 0u;
        valuation += static_cast<int>(still & (1u - bit));
        still &= 1u - bit;
    }
    Bn odd_part = limit;
    odd_part.shift_right(valuation);

    const int limbs = number.size_;
    const uint32_t n0 = neg_inverse(number.limb_[0]);
    uint32_t modulus[Bn::kLimbs] = {};
    for (int i = 0; i < limbs; ++i) {
        modulus[i] = number.limb_[i];
    }
    uint32_t mont_one[Bn::kLimbs] = {};
    uint32_t mont_limit[Bn::kLimbs] = {};
    to_montgomery(mont_one, one, number);
    to_montgomery(mont_limit, limit, number);

    Bn power;
    if (!mod_exp_montgomery(power, base, odd_part, number)) {
        return 0;
    }
    uint32_t power_limbs[Bn::kLimbs] = {};
    for (int i = 0; i < limbs; ++i) {
        power_limbs[i] = i < power.size_ ? power.limb_[i] : 0;
    }
    Bn one_value;
    one_value.set_u64(1);
    uint32_t one_limbs[Bn::kLimbs] = {};
    one_limbs[0] = 1;
    uint32_t limit_limbs[Bn::kLimbs] = {};
    for (int i = 0; i < limbs; ++i) {
        limit_limbs[i] = i < limit.size_ ? limit.limb_[i] : 0;
    }

    uint32_t accepted = limbs_equal(power_limbs, one_limbs, limbs) | limbs_equal(power_limbs, limit_limbs, limbs);
    uint32_t current[Bn::kLimbs] = {};
    to_montgomery(current, power, number);
    uint32_t squared[Bn::kLimbs] = {};
    for (int round = 1; round < width; ++round) {
        montgomery_mul(squared, current, current, modulus, n0, limbs);
        std::memcpy(current, squared, static_cast<std::size_t>(limbs) * sizeof(uint32_t));
        const uint32_t active = (static_cast<uint32_t>(round) - static_cast<uint32_t>(valuation)) >> 31;
        accepted |= active & limbs_equal(current, mont_limit, limbs);
    }
    return accepted;
}

bool RsaMath::miller_rabin(const Bn& number, const Bn* bases, int base_count) {
    Bn two;
    two.set_u64(2);
    Bn three;
    three.set_u64(3);
    if (number.cmp(two) < 0) {
        return false;
    }
    if (number.cmp(two) == 0 || number.cmp(three) == 0) {
        return true;
    }
    if (!number.is_odd()) {
        return false;
    }

    uint32_t accepted = 1;
    for (int i = 0; i < base_count; ++i) {
        accepted &= witness(number, bases[i]);
    }
    return accepted == 1;
}

bool RsaMath::generate_prime(Bn& prime) {
    int prime_count = 0;
    const uint32_t* primes = small_primes(prime_count);
    const int bytes = kPrimeBits / 8;
    uint8_t buffer[kPrimeBits / 8];
    for (int attempt = 0; attempt < 20000; ++attempt) {
        if (!random_bytes(buffer, bytes)) {
            return false;
        }
        buffer[0] |= 0x80;
        buffer[bytes - 1] |= 0x01;
        prime.set_bytes_be(buffer, bytes);

        bool divisible = false;
        for (int i = 0; i < prime_count; ++i) {
            if (primes[i] == 2) {
                continue;
            }
            if (prime.mod_word(primes[i]) == 0) {
                divisible = true;
                break;
            }
        }
        if (divisible || prime.mod_word(kPublicExponent) == 1) {
            continue;
        }

        Bn bases[kMillerRabinRounds];
        Bn limit = prime;
        Bn one;
        one.set_u64(1);
        Bn::sub(limit, prime, one);
        Bn two;
        two.set_u64(2);
        Bn::sub(limit, limit, two);
        bool bases_ok = true;
        for (int i = 0; i < kMillerRabinRounds; ++i) {
            Bn offset;
            if (!random_below(offset, limit)) {
                bases_ok = false;
                break;
            }
            Bn::add(bases[i], offset, two);
        }
        if (bases_ok && miller_rabin(prime, bases, kMillerRabinRounds)) {
            return true;
        }
    }
    return false;
}

bool RsaMath::generate_key(RsaKey& key) {
    key.e.set_u64(kPublicExponent);
    Bn one;
    one.set_u64(1);
    for (int attempt = 0; attempt < 32; ++attempt) {
        if (!generate_prime(key.p) || !generate_prime(key.q)) {
            return false;
        }
        if (key.p.cmp(key.q) < 0) {
            Bn swap = key.p;
            key.p = key.q;
            key.q = swap;
        }
        if (key.p.cmp(key.q) == 0) {
            continue;
        }
        Bn gap;
        Bn::sub(gap, key.p, key.q);
        if (gap.bit_length() <= kPrimeBits - 100) {
            continue;
        }
        Bn::mul(key.n, key.p, key.q);
        if (key.n.bit_length() != kModulusBits) {
            continue;
        }

        Bn p1;
        Bn q1;
        Bn::sub(p1, key.p, one);
        Bn::sub(q1, key.q, one);
        Bn gcd;
        Bn ignore_x;
        Bn ignore_y;
        extended_gcd(gcd, ignore_x, ignore_y, p1, q1);
        Bn quotient;
        Bn remainder;
        Bn::divmod(quotient, remainder, p1, gcd);
        Bn lambda;
        Bn::mul(lambda, quotient, q1);
        if (!mod_inverse(key.d, key.e, lambda)) {
            continue;
        }
        if (key.d.bit_length() <= kPrimeBits - 100) {
            continue;
        }
        Bn::mod(key.dp, key.d, p1);
        Bn::mod(key.dq, key.d, q1);
        if (!mod_inverse(key.qinv, key.q, key.p)) {
            continue;
        }
        return true;
    }
    return false;
}
