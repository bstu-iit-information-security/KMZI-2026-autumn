#include "common.hpp"

namespace rsa {

BigInt::BigInt() : n_(BN_new()) {
    if (!n_) {
        throw BnError("BN_new failed");
    }
}

BigInt::BigInt(const BigInt& other) : n_(BN_dup(other.n_)) {
    if (!n_) {
        throw BnError("BN_dup failed");
    }
}

BigInt::BigInt(BigInt&& other) noexcept : n_(other.n_) {
    other.n_ = nullptr;
}

BigInt::BigInt(unsigned long v) : BigInt() {
    if (BN_set_word(n_, v) != 1) {
        throw BnError("BN_set_word failed");
    }
}

BigInt::~BigInt() {
    BN_free(n_);
}

BigInt& BigInt::operator=(const BigInt& other) {
    if (this != &other) {
        if (BN_copy(n_, other.n_) == nullptr) {
            throw BnError("BN_copy failed");
        }
    }
    return *this;
}

BigInt& BigInt::operator=(BigInt&& other) noexcept {
    if (this != &other) {
        BN_free(n_);
        n_ = other.n_;
        other.n_ = nullptr;
    }
    return *this;
}

BN_CTX* BigInt::ctx() {
    thread_local BN_CTX* c = BN_CTX_new();
    if (!c) {
        throw BnError("BN_CTX_new failed");
    }
    return c;
}

BigInt BigInt::from_dec(const char* s) {
    BigInt r;
    if (BN_dec2bn(&r.n_, s) == 0) {
        throw BnError("BN_dec2bn failed");
    }
    return r;
}

BigInt BigInt::from_hex(const char* s) {
    BigInt r;
    if (BN_hex2bn(&r.n_, s) == 0) {
        throw BnError("BN_hex2bn failed");
    }
    return r;
}

BigInt BigInt::from_bytes_be(const uint8_t* p, std::size_t n) {
    BigInt r;
    if (BN_bin2bn(p, static_cast<int>(n), r.n_) == nullptr) {
        throw BnError("BN_bin2bn failed");
    }
    return r;
}

BigInt BigInt::random_bits(int bits, bool top_odd) {
    BigInt r;
    int top = 1;
    int bottom = top_odd ? 1 : 0;
    if (BN_rand(r.n_, bits, top, bottom) != 1) {
        throw BnError("BN_rand failed");
    }
    return r;
}

std::string BigInt::to_dec() const {
    char* s = BN_bn2dec(n_);
    if (!s) {
        throw BnError("BN_bn2dec failed");
    }
    std::string out(s);
    OPENSSL_free(s);
    return out;
}

std::string BigInt::to_hex() const {
    char* s = BN_bn2hex(n_);
    if (!s) {
        throw BnError("BN_bn2hex failed");
    }
    std::string out(s);
    OPENSSL_free(s);
    return out;
}

std::vector<uint8_t> BigInt::to_bytes_be(std::size_t width) const {
    std::vector<uint8_t> out(width, 0);
    to_bytes_be(out.data(), width);
    return out;
}

void BigInt::to_bytes_be(uint8_t* out, std::size_t width) const {
    std::memset(out, 0, width);
    int n = BN_num_bytes(n_);
    if (n < 0 || static_cast<std::size_t>(n) > width) {
        throw BnError("integer too large for I2OSP width");
    }
    BN_bn2bin(n_, out + (width - static_cast<std::size_t>(n)));
}

int BigInt::bit_length() const {
    return BN_num_bits(n_);
}

int BigInt::byte_length() const {
    return BN_num_bytes(n_);
}

bool BigInt::is_zero() const {
    return BN_is_zero(n_) == 1;
}

bool BigInt::is_odd() const {
    return BN_is_odd(n_) == 1;
}

bool BigInt::bit_set(int i) const {
    return BN_is_bit_set(n_, i) == 1;
}

int BigInt::cmp(const BigInt& o) const {
    return BN_cmp(n_, o.n_);
}

BigInt BigInt::add(const BigInt& o) const {
    BigInt r;
    if (BN_add(r.n_, n_, o.n_) != 1) {
        throw BnError("BN_add failed");
    }
    return r;
}

BigInt BigInt::sub(const BigInt& o) const {
    BigInt r;
    if (BN_sub(r.n_, n_, o.n_) != 1) {
        throw BnError("BN_sub failed");
    }
    return r;
}

BigInt BigInt::mul(const BigInt& o) const {
    BigInt r;
    if (BN_mul(r.n_, n_, o.n_, ctx()) != 1) {
        throw BnError("BN_mul failed");
    }
    return r;
}

BigInt BigInt::div(const BigInt& o) const {
    BigInt r;
    if (BN_div(r.n_, nullptr, n_, o.n_, ctx()) != 1) {
        throw BnError("BN_div failed");
    }
    return r;
}

BigInt BigInt::mod(const BigInt& m) const {
    BigInt r;
    if (BN_nnmod(r.n_, n_, m.n_, ctx()) != 1) {
        throw BnError("BN_nnmod failed");
    }
    return r;
}

BigInt BigInt::mod_add(const BigInt& o, const BigInt& m) const {
    BigInt r;
    if (BN_mod_add(r.n_, n_, o.n_, m.n_, ctx()) != 1) {
        throw BnError("BN_mod_add failed");
    }
    return r;
}

BigInt BigInt::mod_sub(const BigInt& o, const BigInt& m) const {
    BigInt r;
    if (BN_mod_sub(r.n_, n_, o.n_, m.n_, ctx()) != 1) {
        throw BnError("BN_mod_sub failed");
    }
    return r;
}

BigInt BigInt::mod_mul(const BigInt& o, const BigInt& m) const {
    BigInt r;
    if (BN_mod_mul(r.n_, n_, o.n_, m.n_, ctx()) != 1) {
        throw BnError("BN_mod_mul failed");
    }
    return r;
}

}   