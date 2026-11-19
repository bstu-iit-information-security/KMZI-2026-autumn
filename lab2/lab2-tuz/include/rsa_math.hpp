#pragma once

#include <cstddef>
#include <cstdint>

class Bn {
public:
    static constexpr int kLimbs = 192;

    void clear();
    void set_u64(uint64_t value);
    void set_bytes_be(const uint8_t* data, int length);
    void to_bytes_be(uint8_t* data, int length) const;

    int bit_length() const;
    bool bit(int index) const;
    bool is_zero() const;
    bool is_odd() const;
    bool fits_u64() const;
    uint64_t as_u64() const;
    int cmp(const Bn& other) const;

    static void add(Bn& result, const Bn& left, const Bn& right);
    static void sub(Bn& result, const Bn& left, const Bn& right);
    static void mul(Bn& result, const Bn& left, const Bn& right);
    static void divmod(Bn& quotient, Bn& remainder, const Bn& left, const Bn& right);
    static void mod(Bn& result, const Bn& value, const Bn& modulus);

private:
    uint32_t limb_[kLimbs]{};
    int size_ = 0;
    bool negative_ = false;

    void trim();
    void shift_left_one();
    void shift_right(int bits);
    void set_bit(int index);
    uint32_t mod_word(uint32_t word) const;

    friend class RsaMath;
};

struct RsaKey {
    Bn n;
    Bn e;
    Bn d;
    Bn p;
    Bn q;
    Bn dp;
    Bn dq;
    Bn qinv;
};

class RsaMath {
public:
    static constexpr int kModulusBits = 3072;
    static constexpr int kPrimeBits = kModulusBits / 2;
    static constexpr uint32_t kPublicExponent = 65537;
    static constexpr int kMillerRabinRounds = 5;

    static bool mod_exp(Bn& result, const Bn& base, const Bn& exponent, const Bn& modulus);
    static bool mod_inverse(Bn& result, const Bn& value, const Bn& modulus);
    static bool extended_gcd(Bn& gcd, Bn& x, Bn& y, const Bn& left, const Bn& right);
    static bool miller_rabin(const Bn& number, const Bn* bases, int base_count);
    static bool generate_key(RsaKey& key);

private:
    static bool random_bytes(uint8_t* data, int length);
    static bool random_below(Bn& result, const Bn& limit);
    static bool mod_exp_binary(Bn& result, const Bn& base, const Bn& exponent, const Bn& modulus);
    static bool mod_exp_montgomery(Bn& result, const Bn& base, const Bn& exponent, const Bn& modulus);
    static void to_montgomery(uint32_t* out, const Bn& value, const Bn& modulus);
    static uint32_t witness(const Bn& number, const Bn& base);
    static bool generate_prime(Bn& prime);
};
