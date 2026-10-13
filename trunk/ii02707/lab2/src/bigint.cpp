#include "bigint.hpp"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdexcept>
#include <algorithm>

static void check(int ok, const char* what) {
    if (!ok) {
        char buf[256];
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
        throw std::runtime_error(std::string("OpenSSL error in ") + what + ": " + buf);
    }
}

BigInt::BigInt() : bn_(BN_new()) { if (!bn_) throw std::bad_alloc(); }
BigInt::BigInt(uint64_t v) : bn_(BN_new()) {
    if (!bn_) throw std::bad_alloc();
    check(BN_set_word(bn_, (unsigned long)v) == 1, "BN_set_word");
}

BigInt::BigInt(const BigInt& o) : bn_(BN_dup(o.bn_)) {
    if (!bn_) throw std::bad_alloc();
}
BigInt::BigInt(BigInt&& o) noexcept : bn_(o.bn_) { o.bn_ = nullptr; }

BigInt& BigInt::operator=(const BigInt& o) {
    if (this != &o) {
        BIGNUM* tmp = BN_dup(o.bn_);
        if (!tmp) throw std::bad_alloc();
        release();
        bn_ = tmp;
    }
    return *this;
}
BigInt& BigInt::operator=(BigInt&& o) noexcept {
    if (this != &o) { release(); bn_ = o.bn_; o.bn_ = nullptr; }
    return *this;
}
BigInt::~BigInt() { release(); }

BigInt BigInt::from_bytes(const uint8_t* data, size_t len) {
    BigInt r;
    BIGNUM* p = BN_bin2bn(data, (int)len, r.bn_);
    if (!p) throw std::runtime_error("BN_bin2bn failed");
    return r;
}
BigInt BigInt::from_bytes(const std::vector<uint8_t>& v) {
    return from_bytes(v.data(), v.size());
}

std::vector<uint8_t> BigInt::to_bytes() const {
    int n = BN_num_bytes(bn_);
    std::vector<uint8_t> out(n);
    BN_bn2bin(bn_, out.data());
    return out;
}
std::vector<uint8_t> BigInt::to_bytes_padded(size_t len) const {
    std::vector<uint8_t> raw = to_bytes();
    if (raw.size() > len) throw std::runtime_error("BigInt too large for padded bytes");
    std::vector<uint8_t> out(len, 0);
    std::copy(raw.begin(), raw.end(), out.begin() + (len - raw.size()));
    return out;
}

BigInt BigInt::operator+(const BigInt& o) const {
    BigInt r; check(BN_add(r.bn_, bn_, o.bn_) == 1, "BN_add"); return r;
}
BigInt BigInt::operator-(const BigInt& o) const {
    BigInt r; check(BN_sub(r.bn_, bn_, o.bn_) == 1, "BN_sub"); return r;
}
BigInt BigInt::operator*(const BigInt& o) const {
    BigInt r;
    BN_CTX* ctx = BN_CTX_new();
    check(BN_mul(r.bn_, bn_, o.bn_, ctx) == 1, "BN_mul");
    BN_CTX_free(ctx);
    return r;
}
BigInt BigInt::operator/(const BigInt& o) const {
    BigInt q, rem;
    BN_CTX* ctx = BN_CTX_new();
    check(BN_div(q.bn_, rem.bn_, bn_, o.bn_, ctx) == 1, "BN_div");
    BN_CTX_free(ctx);
    return q;
}
BigInt BigInt::operator%(const BigInt& o) const {
    BigInt r;
    BN_CTX* ctx = BN_CTX_new();
    check(BN_mod(r.bn_, bn_, o.bn_, ctx) == 1, "BN_mod");
    BN_CTX_free(ctx);
    return r;
}
BigInt& BigInt::operator+=(const BigInt& o) {
    check(BN_add(bn_, bn_, o.bn_) == 1, "BN_add"); return *this;
}
BigInt& BigInt::operator-=(const BigInt& o) {
    check(BN_sub(bn_, bn_, o.bn_) == 1, "BN_sub"); return *this;
}

bool BigInt::operator==(const BigInt& o) const { return BN_cmp(bn_, o.bn_) == 0; }
bool BigInt::operator!=(const BigInt& o) const { return BN_cmp(bn_, o.bn_) != 0; }
bool BigInt::operator< (const BigInt& o) const { return BN_cmp(bn_, o.bn_) <  0; }
bool BigInt::operator> (const BigInt& o) const { return BN_cmp(bn_, o.bn_) >  0; }
bool BigInt::operator<=(const BigInt& o) const { return BN_cmp(bn_, o.bn_) <= 0; }
bool BigInt::operator>=(const BigInt& o) const { return BN_cmp(bn_, o.bn_) >= 0; }

BigInt BigInt::mod_exp(const BigInt& base, const BigInt& exp, const BigInt& mod) {
    BigInt r;
    BN_CTX* ctx = BN_CTX_new();
    check(BN_mod_exp(r.bn_, base.bn_, exp.bn_, mod.bn_, ctx) == 1, "BN_mod_exp");
    BN_CTX_free(ctx);
    return r;
}
BigInt BigInt::mod_inv(const BigInt& a, const BigInt& mod) {
    BigInt r;
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = BN_mod_inverse(r.bn_, a.bn_, mod.bn_, ctx);
    BN_CTX_free(ctx);
    if (!p) throw std::runtime_error("mod_inv: no inverse (gcd != 1)");
    return r;
}
BigInt BigInt::mod_mul(const BigInt& a, const BigInt& b, const BigInt& mod) {
    BigInt r;
    BN_CTX* ctx = BN_CTX_new();
    check(BN_mod_mul(r.bn_, a.bn_, b.bn_, mod.bn_, ctx) == 1, "BN_mod_mul");
    BN_CTX_free(ctx);
    return r;
}
BigInt BigInt::mod_add(const BigInt& a, const BigInt& b, const BigInt& mod) {
    BigInt r;
    BN_CTX* ctx = BN_CTX_new();
    check(BN_mod_add(r.bn_, a.bn_, b.bn_, mod.bn_, ctx) == 1, "BN_mod_add");
    BN_CTX_free(ctx);
    return r;
}
BigInt BigInt::mod_sub(const BigInt& a, const BigInt& b, const BigInt& mod) {
    BigInt r;
    BN_CTX* ctx = BN_CTX_new();
    check(BN_mod_sub(r.bn_, a.bn_, b.bn_, mod.bn_, ctx) == 1, "BN_mod_sub");
    BN_CTX_free(ctx);
    return r;
}

BigInt BigInt::gcd(const BigInt& a, const BigInt& b) {
    BigInt r;
    BN_CTX* ctx = BN_CTX_new();
    check(BN_gcd(r.bn_, a.bn_, b.bn_, ctx) == 1, "BN_gcd");
    BN_CTX_free(ctx);
    return r;
}

int  BigInt::bit_length() const { return BN_num_bits(bn_); }
int  BigInt::byte_length() const { return BN_num_bytes(bn_); }
bool BigInt::is_zero() const { return BN_is_zero(bn_); }
bool BigInt::is_one()  const { return BN_is_one(bn_); }
bool BigInt::is_odd()  const { return BN_is_odd(bn_); }

bool BigInt::is_prime(int checks) const {
    BN_CTX* ctx = BN_CTX_new();
    int res = 0;

    int r = BN_check_prime(bn_, ctx, nullptr);
    BN_CTX_free(ctx);
    (void)checks;
    return r == 1;
}

BigInt BigInt::random_bits(int bits) {
    BigInt r;
    check(BN_rand(r.bn_, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) == 1, "BN_rand");
    return r;
}
BigInt BigInt::random_range(const BigInt& lo, const BigInt& hi) {
    BigInt range = hi - lo;
    BigInt r;
    BN_CTX* ctx = BN_CTX_new();
    check(BN_rand_range(r.bn_, range.bn_) == 1, "BN_rand_range");
    BN_CTX_free(ctx);
    return r + lo;
}

std::string BigInt::to_decimal() const {
    char* s = BN_bn2dec(bn_);
    std::string r(s ? s : "0");
    OPENSSL_free(s);
    return r;
}